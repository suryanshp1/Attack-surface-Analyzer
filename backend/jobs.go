package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RuntimeInfo struct {
	LiveScanning         bool `json:"liveScanning"`
	Workers              int  `json:"workers"`
	Evidence             bool `json:"evidence"`
	VerificationRequired bool `json:"verificationRequired"`
}
type Checkpoint struct {
	CrawlIncomplete []string            `json:"crawlIncomplete,omitempty"`
	CrawlResults    map[string]bool     `json:"crawlResults,omitempty"`
	PortIncomplete  []string            `json:"portIncomplete,omitempty"`
	PortResults     map[string][]int    `json:"portResults,omitempty"`
	History         []Endpoint          `json:"history,omitempty"`
	SourceIssues    []string            `json:"sourceIssues,omitempty"`
	ServiceCoverage map[string][]string `json:"serviceCoverage,omitempty"`
	KnownSecrets    []Finding           `json:"knownSecrets,omitempty"`
	SecretCoverage  map[string][]string `json:"secretCoverage,omitempty"`
	Hosts           map[string][]string `json:"hosts,omitempty"`
	DNS             map[string][]string `json:"dns,omitempty"`
	Assets          []Asset             `json:"assets,omitempty"`
	Findings        []Finding           `json:"findings,omitempty"`
	Covered         []string            `json:"covered,omitempty"`
	Coverage        map[string][]string `json:"coverage,omitempty"`
	Templates       []string            `json:"templates,omitempty"`
	Blocked         []string            `json:"blocked,omitempty"`
	Known           []string            `json:"known,omitempty"`
}
type WorkerInfo struct {
	ID       string            `json:"id"`
	SeenAt   string            `json:"seenAt"`
	Versions map[string]string `json:"versions"`
	ScanID   string            `json:"scanId"`
}
type Claim struct {
	Scan   Scan   `json:"scan"`
	Target Target `json:"target"`
	Permit string `json:"permit"`
	Proxy  string `json:"proxy"`
	DNS    string `json:"dns"`
}
type Permit struct {
	Scan    string `json:"scan"`
	Root    string `json:"root"`
	Expires int64  `json:"expires"`
	Lease   string `json:"lease"`
}

func signPermit(p Permit, secret string) string {
	b, _ := json.Marshal(p)
	value := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(value))
	return value + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func checkPermit(value, secret string) (Permit, error) {
	var p Permit
	parts := strings.Split(value, ".")
	if len(parts) != 2 || secret == "" {
		return p, errors.New("missing scan permit")
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return p, err
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(parts[0]))
	if !hmac.Equal(mac, m.Sum(nil)) {
		return p, errors.New("invalid scan permit")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Expires < time.Now().Unix() || p.Scan == "" || p.Lease == "" || !validDomain(p.Root) {
		return p, errors.New("expired or invalid scope permit")
	}
	return p, nil
}
func activeScan(status string) bool {
	return status == "running" || status == "queued" || status == "retrying"
}
func inScope(host, root string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == root || strings.HasSuffix(host, "."+root)
}
func fingerprint(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:16])
}
func (s *Server) publicState() State {
	out := s.state
	out.AccessKeys = append([]AccessKey{}, s.state.AccessKeys...)
	for i := range out.AccessKeys {
		out.AccessKeys[i].Hash = ""
	}
	count := 0
	for _, worker := range s.workers {
		seen, _ := time.Parse(time.RFC3339, worker.SeenAt)
		if worker.ID != "egress-gateway" && time.Since(seen) < 30*time.Second {
			count++
		}
	}
	out.Runtime = RuntimeInfo{s.liveEnabled, count, s.evidence != nil, !s.allowUnverified}
	out.Targets = append([]Target{}, s.state.Targets...)
	for i := range out.Targets {
		out.Targets[i].CanScan = s.targetCanScan(&out.Targets[i])
	}
	out.Assets = []Asset{}
	for _, a := range s.state.Assets {
		if !a.Removed {
			a.ProbeStatus = "Not probed"
			if a.Status > 0 {
				a.ProbeStatus = "HTTP " + strconv.Itoa(a.Status)
			} else {
				for _, port := range a.Ports {
					if webPort(strconv.Itoa(port)) {
						a.ProbeStatus = "No HTTP response recorded"
						break
					}
				}
			}
			if a.Blocked {
				a.ProbeStatus = "Probe unavailable"
			}
			if ip, err := netip.ParseAddr(a.IP); err == nil && !publicIP(ip) {
				a.ProbeStatus = "Excluded · non-public address"
			}
			out.Assets = append(out.Assets, a)
		}
	}
	out.Findings = append([]Finding{}, s.state.Findings...)
	for i := range out.Findings {
		clarifyCertificateFinding(&out.Findings[i])
	}
	out.Scans = append([]Scan{}, s.state.Scans...)
	for i := range out.Scans {
		sc := &out.Scans[i]
		sc.Stages = append([]Stage{}, sc.Stages...)
		reconcileTerminalStages(sc)
		sc.Coverage = ScanCoverage{len(sc.Checkpoint.CrawlResults), len(sc.Checkpoint.CrawlIncomplete), len(sc.Checkpoint.PortResults), len(sc.Checkpoint.PortIncomplete)}
		out.Scans[i].ExcludedHosts = excludedHosts(out.Scans[i].Checkpoint)
		if out.Scans[i].Status == "partial" && strings.Contains(out.Scans[i].Error, "Some hosts were blocked") {
			out.Scans[i].Error = coverageSummary(out.Scans[i].Checkpoint)
		}
		out.Scans[i].Checkpoint = Checkpoint{}
		out.Scans[i].Lease = ""
		out.Scans[i].LeaseUntil = ""
	}
	return out
}

// Legacy snapshots can have a terminal scan with an active child stage.
func reconcileTerminalStages(sc *Scan) {
	if activeScan(sc.Status) {
		return
	}
	for i := range sc.Stages {
		if sc.Stages[i].Status == "running" {
			sc.Stages[i].Status = "interrupted"
		}
		if sc.Stages[i].Status == "pending" {
			sc.Stages[i].Status = "not_run"
		}
	}
}

func pinnedResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
	}}
}

func (s *Server) targetCanScan(t *Target) bool {
	return t != nil && !t.Demo && (s.allowUnverified || t.Status == "verified")
}
func (s *Server) checkScanOwnership(ctx context.Context, t *Target) error {
	if !s.targetCanScan(t) {
		return errors.New("Target is not eligible for scanning")
	}
	if s.allowUnverified {
		return nil
	}
	return s.verifyTarget(ctx, t)
}

var errDNSUnavailable = errors.New("DNS resolver unavailable")

// The API has no public egress in Compose; ownership queries use the DNS relay.
// The gateway itself keeps its public resolver pinned through pinnedResolver.
func ownershipResolver() *net.Resolver {
	address := os.Getenv("EGRESS_DNS")
	if address == "" {
		address = "1.1.1.1:53"
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
	}}
}
func (s *Server) verifyTarget(ctx context.Context, t *Target) error {
	if t.Demo {
		return errors.New("Legacy sample targets cannot be scanned")
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	lookup := ownershipResolver().LookupTXT
	if s.lookupTXT != nil {
		lookup = s.lookupTXT
	}
	name := "_surfacer." + t.Domain
	records, err := lookup(c, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return fmt.Errorf("No TXT record is published at %s. Add the verification value shown in Targets to your DNS provider and retry after propagation.", name)
		}
		log.Printf("ownership DNS lookup failed for %s: %v", name, err)
		return fmt.Errorf("%w: ownership could not be checked. Retry shortly; if this persists, check the DNS gateway connection.", errDNSUnavailable)
	}
	for _, record := range records {
		if record == t.Token {
			t.LastVerified = now()
			return nil
		}
	}
	return fmt.Errorf("The TXT record at %s does not match this target's verification value. Copy the exact value shown in Targets and retry after propagation.", name)
}
func (s *Server) makeScan(t Target, trigger string) Scan {
	sc := newScan(t, trigger, s.state.Settings.Rate)
	sc.Concurrency = s.state.Settings.Concurrency
	for _, f := range s.state.Findings {
		if f.TargetID == t.ID && strings.HasPrefix(f.Template, "gitleaks:") {
			sc.Checkpoint.KnownSecrets = append(sc.Checkpoint.KnownSecrets, Finding{Host: f.Host, Template: f.Template, MatchedAt: f.MatchedAt})
		}
	}
	{
		sc.Status = "queued"
		for i := range sc.Stages {
			sc.Stages[i].Status = "pending"
		}
		for _, a := range s.state.Assets {
			if a.TargetID == t.ID {
				sc.Checkpoint.Known = append(sc.Checkpoint.Known, a.Host)
			}
		}
	}
	return sc
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live := 0
	for _, worker := range s.workers {
		seen, _ := time.Parse(time.RFC3339, worker.SeenAt)
		if worker.ID != "egress-gateway" && time.Since(seen) < 30*time.Second {
			live++
		}
	}
	respond(w, 200, map[string]any{"status": "ok", "liveScanning": s.liveEnabled, "workers": live, "storage": s.db != nil, "evidence": s.evidence != nil})
}
func (s *Server) workerAPI(w http.ResponseWriter, r *http.Request) {
	token := os.Getenv("WORKER_TOKEN")
	given := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(given)) != 1 {
		fail(w, 401, "Worker authentication required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, _ := json.Marshal(s.state)
	var p struct {
		Worker      string            `json:"worker"`
		Versions    map[string]string `json:"versions"`
		ScanID      string            `json:"scanId"`
		Lease       string            `json:"lease"`
		Stage       int               `json:"stage"`
		Status      string            `json:"status"`
		Log         string            `json:"log"`
		Error       string            `json:"error"`
		Checkpoint  Checkpoint        `json:"checkpoint"`
		Permit      string            `json:"permit"`
		Destination string            `json:"destination"`
		Port        int               `json:"port"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		fail(w, 400, "Invalid worker payload")
		return
	}
	if len(p.Worker) < 3 || len(p.Worker) > 100 {
		fail(w, 400, "Worker identity required")
		return
	}
	if s.workers == nil {
		s.workers = map[string]WorkerInfo{}
	}
	s.workers[p.Worker] = WorkerInfo{p.Worker, now(), p.Versions, p.ScanID}
	save := func() bool {
		if err := s.save(); err != nil {
			_ = json.Unmarshal(before, &s.state)
			fail(w, 500, "Could not persist worker update")
			return false
		}
		return true
	}
	if r.URL.Path == "/internal/tcp-authorize" {
		root, ok := s.tcpAuthorized(p.ScanID, p.Lease, p.Destination, p.Port)
		if !ok {
			fail(w, 403, "TCP scope or lease rejected")
			return
		}
		respond(w, 200, map[string]any{"root": root, "allowed": true})
		return
	}
	if r.URL.Path == "/internal/claim" {
		if s.state.Settings.Paused {
			respond(w, 200, map[string]any{"scan": nil})
			return
		}
		for i := range s.state.Scans {
			sc := &s.state.Scans[i]
			if sc.Demo || (sc.Status != "queued" && sc.Status != "retrying") {
				continue
			}
			if sc.RetryAt != "" {
				retry, _ := time.Parse(time.RFC3339, sc.RetryAt)
				if time.Now().Before(retry) {
					continue
				}
			}
			var target *Target
			for j := range s.state.Targets {
				if s.state.Targets[j].ID == sc.TargetID {
					target = &s.state.Targets[j]
				}
			}
			if !s.targetCanScan(target) {
				sc.Status = "canceled"
				sc.Error = "Target ownership is not verified"
				sc.FinishedAt = now()
				continue
			}
			if err := s.checkScanOwnership(r.Context(), target); err != nil {
				target.Status = "paused"
				sc.Status = "canceled"
				sc.Error = err.Error()
				sc.FinishedAt = now()
				s.audit("Scan blocked by ownership verification", target.Domain)
				if !save() {
					return
				}
				continue
			}
			sc.Worker = p.Worker
			sc.Lease = id()
			sc.LeaseUntil = time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
			if sc.Attempts == 0 {
				sc.StartedAt = now()
			}
			sc.Status = "running"
			sc.Attempts++
			sc.Error = ""
			s.auditActor("Worker claimed scan", sc.Domain+" · "+p.Worker, p.Worker)
			if !save() {
				return
			}
			proxy := os.Getenv("EGRESS_PROXY")
			if proxy == "" {
				proxy = "http://gateway:3128"
			}
			dns := os.Getenv("EGRESS_DNS")
			if dns == "" {
				dns = "172.30.88.3:5353"
			}
			respond(w, 200, Claim{*sc, *target, signPermit(Permit{sc.ID, sc.Domain, time.Now().Add(62 * time.Minute).Unix(), sc.Lease}, s.gatewaySecret), proxy, dns})
			return
		}
		if !save() {
			return
		}
		respond(w, 200, map[string]any{"scan": nil})
		return
	}
	if r.URL.Path == "/internal/authorize" {
		permit, err := checkPermit(p.Permit, s.gatewaySecret)
		if err != nil || s.state.Settings.Paused {
			fail(w, 403, "Scope permit rejected")
			return
		}
		for _, scan := range s.state.Scans {
			if scan.ID == permit.Scan && scan.Domain == permit.Root && scan.Status == "running" && subtle.ConstantTimeCompare([]byte(scan.Lease), []byte(permit.Lease)) == 1 {
				until, _ := time.Parse(time.RFC3339, scan.LeaseUntil)
				if time.Now().Before(until) {
					for _, target := range s.state.Targets {
						if target.ID == scan.TargetID && s.targetCanScan(&target) {
							respond(w, 200, map[string]bool{"allowed": true})
							return
						}
					}
				}
			}
		}
		fail(w, 403, "Scan no longer active")
		return
	}
	index := -1
	for i, sc := range s.state.Scans {
		if sc.ID == p.ScanID {
			index = i
		}
	}
	if index < 0 {
		fail(w, 404, "Scan not found")
		return
	}
	sc := &s.state.Scans[index]
	if sc.Worker != p.Worker || sc.Lease == "" || subtle.ConstantTimeCompare([]byte(sc.Lease), []byte(p.Lease)) != 1 || sc.Status != "running" || s.state.Settings.Paused {
		fail(w, 409, "Lease lost or scan canceled")
		return
	}
	sc.LeaseUntil = time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
	switch r.URL.Path {
	case "/internal/heartbeat":
		if !save() {
			return
		}
		respond(w, 200, map[string]bool{"active": true})
		return
	case "/internal/release":
		sc.Status = "queued"
		sc.Lease = ""
		sc.Worker = ""
		for i := range sc.Stages {
			if sc.Stages[i].Status == "running" {
				sc.Stages[i].Status = "pending"
			}
		}
		s.auditActor("Worker released scan", sc.Domain, p.Worker)
	case "/internal/stage":
		if p.Stage < 0 || p.Stage >= len(sc.Stages) || p.Status != "running" && p.Status != "progress" && p.Status != "completed" && p.Status != "failed" {
			fail(w, 400, "Invalid stage update")
			return
		}
		for j := 0; j < p.Stage; j++ {
			if sc.Stages[j].Status != "completed" {
				fail(w, 409, "Previous stages must complete first")
				return
			}
		}
		if sc.Stages[p.Stage].Status == "completed" && p.Status != "completed" {
			fail(w, 409, "Completed stage cannot restart")
			return
		}
		if p.Status == "running" {
			var target *Target
			for j := range s.state.Targets {
				if s.state.Targets[j].ID == sc.TargetID {
					target = &s.state.Targets[j]
				}
			}
			if !s.targetCanScan(target) {
				fail(w, 409, "Ownership lost")
				return
			}
			if err := s.checkScanOwnership(r.Context(), target); err != nil {
				target.Status = "paused"
				sc.Status = "canceled"
				sc.Error = err.Error()
				sc.FinishedAt = now()
				_ = save()
				fail(w, 409, "Ownership proof no longer matches")
				return
			}
			sc.Stages[p.Stage].Attempts++
		}
		for i := range p.Checkpoint.Findings {
			f := &p.Checkpoint.Findings[i]
			f.Evidence = redact(capString(f.Evidence, 16<<10))
			f.Title = capString(f.Title, 300)
			f.Description = capString(f.Description, 2000)
			f.Remediation = capString(f.Remediation, 2000)
		}
		if err := validateCheckpoint(p.Checkpoint, sc.Domain); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if p.Status == "progress" {
			if sc.Stages[p.Stage].Status != "running" || (sc.Stages[p.Stage].Name != "Port discovery" && sc.Stages[p.Stage].Name != "Endpoint crawling") {
				fail(w, 409, "Progress requires a running port or crawl stage")
				return
			}
			sc.Checkpoint = p.Checkpoint
		} else {
			sc.Stages[p.Stage].Status = p.Status
		}
		sc.Stages[p.Stage].Log = redact(capString(p.Log, 4000))
		if p.Status == "completed" {
			if s.evidence != nil {
				data, _ := json.Marshal(p.Checkpoint)
				if err := s.evidence.put(r.Context(), "scans/"+sc.ID+"/stage-"+fmt.Sprint(p.Stage)+".json", data); err != nil {
					_ = json.Unmarshal(before, &s.state)
					fail(w, 503, "Evidence store unavailable; stage was not committed")
					return
				}
			}
			sc.Checkpoint = p.Checkpoint
			sc.Progress = (p.Stage + 1) * 100 / len(sc.Stages)
			sc.Assets = len(p.Checkpoint.Assets)
			sc.Findings = len(p.Checkpoint.Findings)
		}
		if p.Status == "failed" {
			sc.Error = redact(capString(p.Error, 1000))
			sc.Stages[p.Stage].Log = sc.Error
			sc.Checkpoint = p.Checkpoint
			if sc.Attempts < 3 {
				sc.Status = "retrying"
				sc.RetryAt = time.Now().Add(time.Duration(sc.Attempts*10) * time.Second).UTC().Format(time.RFC3339)
				sc.Stages[p.Stage].Status = "pending"
			} else {
				sc.Status = "partial"
				sc.FinishedAt = now()
				s.normalize(sc, false)
			}
			sc.Lease = ""
			s.audit("Scan stage failed", sc.Domain+" · "+sc.Stages[p.Stage].Name+": "+sc.Error)
		}
	case "/internal/complete":
		for _, st := range sc.Stages {
			if st.Status != "completed" {
				fail(w, 409, "All stages must complete")
				return
			}
		}
		for _, observed := range sc.Checkpoint.Assets {
			if observed.URL != "" {
				continue
			}
			for _, previous := range s.state.Assets {
				if previous.TargetID == sc.TargetID && previous.Host == observed.Host && previous.URL != "" {
					sc.Checkpoint.Blocked = append(sc.Checkpoint.Blocked, observed.Host)
				}
			}
		}
		sc.Status = "completed"
		if len(coverageBlockers(sc.Checkpoint)) > 0 || len(sc.Checkpoint.PortIncomplete) > 0 || len(sc.Checkpoint.CrawlIncomplete) > 0 {
			sc.Status = "partial"
			sc.Error = coverageSummary(sc.Checkpoint)
		}
		sc.FinishedAt = now()
		sc.Progress = 100
		s.normalize(sc, sc.Status == "completed")
		sc.Lease = ""
		s.auditActor("Scan "+sc.Status, sc.Domain+" · "+p.Worker, p.Worker)
	default:
		fail(w, 404, "Unknown worker endpoint")
		return
	}
	if !save() {
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func capString(s string, n int) string {
	if len(s) > n {
		suffix := "\n[truncated]"
		if n <= len(suffix) {
			return s[:n]
		}
		return s[:n-len(suffix)] + suffix
	}
	return s
}
func validateCheckpoint(cp Checkpoint, root string) error {
	if len(cp.CrawlResults) > 10000 || len(cp.CrawlIncomplete) > 10000 || len(cp.Hosts) > 1000 || len(cp.Assets) > 1000 || len(cp.Findings) > 2000 || len(cp.History) > 2000 {
		return errors.New("Scan result exceeds limits")
	}
	for h := range cp.Hosts {
		if !inScope(h, root) || !domainPattern.MatchString(h) {
			return errors.New("Discovery result escaped verified scope")
		}
	}
	for h := range cp.DNS {
		if !inScope(h, root) {
			return errors.New("DNS result escaped scope")
		}
	}
	for _, e := range cp.History {
		u, ok := scopedEndpoint(e.URL, root)
		if !ok || u.RawQuery != "" || !e.Historical {
			return errors.New("Historical endpoint escaped scope or contains parameter values")
		}
	}
	for origin := range cp.ServiceCoverage {
		u, ok := scopedEndpoint(origin, root)
		if !ok || u.RawQuery != "" {
			return errors.New("Service coverage escaped scope")
		}
	}
	for _, seed := range cp.CrawlIncomplete {
		if _, ok := scopedEndpoint(seed, root); !ok || serviceOrigin(seed) != seed {
			return errors.New("Incomplete crawl escaped service scope")
		}
	}
	for seed := range cp.CrawlResults {
		if _, ok := scopedEndpoint(seed, root); !ok || serviceOrigin(seed) != seed {
			return errors.New("Crawl coverage escaped service scope")
		}
	}
	for _, host := range cp.PortIncomplete {
		if !inScope(host, root) {
			return errors.New("Incomplete port scope escaped target")
		}
	}
	for ip, ports := range cp.PortResults {
		known := false
		for _, addresses := range cp.DNS {
			if contains(addresses, ip) {
				known = true
			}
		}
		if !known || len(ports) > len(commonPorts) {
			return errors.New("Port coverage escaped resolved scope")
		}
		for _, port := range ports {
			if !scanPort(port) {
				return errors.New("Port outside approved profile")
			}
		}
	}
	for _, a := range cp.Assets {
		if len(a.Services) > len(commonPorts) {
			return errors.New("Service limit exceeded")
		}
		for _, svc := range a.Services {
			u, ok := scopedEndpoint(svc.URL, root)
			if !ok || u.Hostname() != a.Host || !webPort(strconv.Itoa(svc.Port)) {
				return errors.New("Service escaped scope")
			}
		}
		if len(a.Endpoints) > 2000 {
			return errors.New("Endpoint limit exceeded")
		}
		for _, e := range a.Endpoints {
			u, ok := scopedEndpoint(e.URL, root)
			if !ok || u.Hostname() != a.Host {
				return errors.New("Endpoint escaped scope")
			}
		}
		if !inScope(a.Host, root) {
			return errors.New("Asset escaped scope")
		}
	}
	for _, f := range cp.Findings {
		if !inScope(f.Host, root) {
			return errors.New("Finding escaped scope")
		}
	}
	for h := range cp.Coverage {
		if !inScope(h, root) {
			return errors.New("Template coverage escaped scope")
		}
	}
	for _, h := range cp.Covered {
		if !inScope(h, root) {
			return errors.New("Coverage escaped scope")
		}
	}
	return nil
}
func (s *Server) maintenance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirty := false
	for i := range s.state.Scans {
		sc := &s.state.Scans[i]
		if sc.Demo || sc.Status != "running" {
			continue
		}
		until, _ := time.Parse(time.RFC3339, sc.LeaseUntil)
		started, _ := time.Parse(time.RFC3339, sc.StartedAt)
		if time.Since(started) > 75*time.Minute {
			sc.Status = "partial"
			sc.Error = "Scan hard deadline exceeded"
			reconcileTerminalStages(sc)
			sc.FinishedAt = now()
			sc.Lease = ""
			s.normalize(sc, false)
			dirty = true
			continue
		}
		if time.Now().After(until) {
			sc.Lease = ""
			sc.Worker = ""
			if sc.Attempts >= 3 {
				sc.Status = "partial"
				sc.Error = "Worker lease expired three times"
				reconcileTerminalStages(sc)
				sc.FinishedAt = now()
				s.normalize(sc, false)
			} else {
				sc.Status = "queued"
			}
			for j := range sc.Stages {
				if sc.Stages[j].Status == "running" {
					sc.Stages[j].Status = "pending"
				}
			}
			s.auditActor("Worker lease recovered", sc.Domain, "Surfacer scheduler")
			dirty = true
		}
	}
	if dirty {
		_ = s.save()
	}
}
func (s *Server) normalize(sc *Scan, successful bool) {
	stamp := now()
	for _, e := range sc.Checkpoint.History {
		e.FirstSeen = stamp
		e.LastSeen = stamp
		found := false
		for i, old := range s.state.History {
			if old.ID == e.ID {
				e.FirstSeen = old.FirstSeen
				s.state.History[i] = e
				found = true
				break
			}
		}
		if !found {
			s.state.History = append(s.state.History, e)
		}
	}
	crawlComplete := false
	for _, stage := range sc.Stages {
		if stage.Name == "Endpoint crawling" && stage.Status == "completed" {
			crawlComplete = true
		}
	}
	seen := map[string]bool{}
	for _, a := range sc.Checkpoint.Assets {
		a.ID = fingerprint(sc.TargetID, a.Host)
		a.TargetID = sc.TargetID
		a.LastSeen = stamp
		a.FirstSeen = stamp
		a.MissingScans = 0
		seen[a.ID] = true
		found := false
		for i, old := range s.state.Assets {
			if old.ID == a.ID {
				a.FirstSeen = old.FirstSeen
				if sc.Checkpoint.PortResults != nil {
					complete := true
					for _, ip := range sc.Checkpoint.DNS[a.Host] {
						if _, ok := sc.Checkpoint.PortResults[ip]; !ok {
							complete = false
						}
					}
					if !complete {
						for _, port := range old.Ports {
							if !contains(intStrings(a.Ports), strconv.Itoa(port)) {
								a.Ports = append(a.Ports, port)
							}
						}
						sort.Ints(a.Ports)
					}
				}
				a.Endpoints = mergeEndpoints(a.Endpoints, old.Endpoints, stamp, successful && crawlComplete && len(sc.Checkpoint.CrawlIncomplete) == 0 && !a.Blocked)
				added, removed, returned := endpointDelta(old.Endpoints, a.Endpoints)
				if added+removed+returned > 0 {
					s.emit("endpoint", "Endpoint inventory changed", fmt.Sprintf("%s · %d new · %d removed · %d returned", a.Host, added, removed, returned), stamp)
				}
				if a.URL == "" && old.URL != "" {
					a.URL = old.URL
					a.Type = old.Type
					a.Status = old.Status
					a.Title = old.Title
					a.Technologies = old.Technologies
					a.TLS = old.TLS
					a.Ports = old.Ports
					a.Blocked = true
				}
				if old.Removed {
					s.emit("asset", "Asset returned", a.Host, stamp)
				}
				if strings.Join(intStrings(old.Ports), ",") != strings.Join(intStrings(a.Ports), ",") {
					s.emit("port", "Ports changed", a.Host+" · "+strings.Join(intStrings(a.Ports), ", "), stamp)
				}
				s.state.Assets[i] = a
				found = true
				break
			}
		}
		if !found {
			a.Endpoints = mergeEndpoints(a.Endpoints, nil, stamp, false)
			s.state.Assets = append(s.state.Assets, a)
			s.emit("asset", "New asset discovered", a.Host, stamp)
		}
	}
	foundIDs := map[string]bool{}
	for _, f := range sc.Checkpoint.Findings {
		f.TargetID = sc.TargetID
		f.ID = fingerprint(sc.TargetID, f.Template, f.Host, f.MatchedAt)
		f.Evidence = redact(capString(f.Evidence, 16<<10))
		f.LastSeen = stamp
		f.FirstSeen = stamp
		f.Notes = []Note{}
		f.Status = "open"
		foundIDs[f.ID] = true
		found := false
		for i, old := range s.state.Findings {
			if old.ID == f.ID {
				f.FirstSeen = old.FirstSeen
				f.Notes = old.Notes
				f.Status = old.Status
				if old.Status == "resolved" {
					f.Status = "open"
					s.emit("finding", "Finding reopened", f.Title+" · "+f.Host, stamp)
				}
				s.state.Findings[i] = f
				found = true
				break
			}
		}
		if s.evidence != nil {
			key := sc.TargetID + "/" + f.ID + "/" + sc.ID + ".txt"
			if err := s.evidence.put(context.Background(), key, []byte(f.Evidence)); err == nil {
				f.EvidenceKey = key
				for i := range s.state.Findings {
					if s.state.Findings[i].ID == f.ID {
						s.state.Findings[i].EvidenceKey = key
					}
				}
			}
		}
		if !found {
			s.state.Findings = append(s.state.Findings, f)
			s.emit("finding", "New "+f.Severity+" exposure", f.Title+" · "+f.Host, stamp)
		}
	}
	if successful {
		coverage := sc.Checkpoint.Coverage

		for i := range s.state.Findings {
			f := &s.state.Findings[i]
			if f.TargetID != sc.TargetID || f.Status != "open" || foundIDs[f.ID] || !contains(coverage[f.Host], f.Template) {
				continue
			}
			if sc.Checkpoint.ServiceCoverage != nil && !strings.HasPrefix(f.Template, "tls-") && !strings.HasPrefix(f.Template, "gitleaks:") && !contains(sc.Checkpoint.ServiceCoverage[serviceOrigin(f.MatchedAt)], f.Template) {
				continue
			}
			f.MissingScans++
			if f.MissingScans >= 2 {
				f.Status = "resolved"
				s.emit("resolved", "Finding resolved", f.Title+" · "+f.Host, stamp)
			}
		}
		for i := range s.state.Assets {
			a := &s.state.Assets[i]
			if a.TargetID != sc.TargetID || seen[a.ID] || a.Removed {
				continue
			}
			if _, checked := sc.Checkpoint.DNS[a.Host]; !checked {
				continue
			}
			if len(sc.Checkpoint.DNS[a.Host]) == 0 {
				a.MissingScans++
				if a.MissingScans >= 2 {
					a.Removed = true
					s.emit("asset", "Asset removed", a.Host, stamp)
				}
			}
		}
	}
	for i := range s.state.Assets {
		a := &s.state.Assets[i]
		if a.TargetID != sc.TargetID {
			continue
		}
		a.Findings = 0
		a.Severity = "none"
		ranks := map[string]int{"none": 5, "info": 4, "low": 3, "medium": 2, "high": 1, "critical": 0}
		for _, f := range s.state.Findings {
			if f.Host == a.Host && f.Status == "open" {
				a.Findings++
				if ranks[f.Severity] < ranks[a.Severity] {
					a.Severity = f.Severity
				}
			}
		}
	}
	for i := range s.state.Targets {
		t := &s.state.Targets[i]
		if t.ID != sc.TargetID {
			continue
		}
		t.LastScan = stamp
		t.Assets = 0
		for _, a := range s.state.Assets {
			if a.TargetID == t.ID && !a.Removed {
				t.Assets++
			}
		}
	}
	s.emit("scan", "Scan "+sc.Status, sc.Domain+" · "+fmt.Sprint(len(sc.Checkpoint.Assets))+" assets", stamp)
}
func (s *Server) emit(kind, title, detail, stamp string) {
	s.state.Events = append([]Event{{id(), kind, title, detail, stamp, "Surfacer"}}, s.state.Events...)
}
func contains(values []string, v string) bool {
	for _, item := range values {
		if item == v {
			return true
		}
	}
	return false
}
func intStrings(values []int) []string {
	out := []string{}
	for _, n := range values {
		out = append(out, fmt.Sprint(n))
	}
	return out
}

// Verification is repeated even when no scans are running. A removed proof cancels leases.
func (s *Server) reverifyOwnedTargets() {
	if s.allowUnverified {
		return
	}
	s.mu.Lock()
	targets := append([]Target{}, s.state.Targets...)
	s.mu.Unlock()
	for _, target := range targets {
		if target.Demo || target.Status != "verified" {
			continue
		}
		err := s.verifyTarget(s.ctx, &target)
		s.mu.Lock()
		for i, t := range s.state.Targets {
			if t.ID != target.ID {
				continue
			}
			if err != nil {
				s.state.Targets[i].Status = "paused"
				for j, scan := range s.state.Scans {
					if scan.TargetID == t.ID && activeScan(scan.Status) {
						s.state.Scans[j].Status = "canceled"
						s.state.Scans[j].FinishedAt = now()
						s.state.Scans[j].Error = "Ownership proof is missing"
					}
				}
				s.audit("Ownership proof lost; scans paused", t.Domain)
			} else {
				s.state.Targets[i].LastVerified = target.LastVerified
			}
		}
		if saveErr := s.save(); saveErr != nil {
			log.Printf("ownership check persistence: %v", saveErr)
		}
		s.mu.Unlock()
	}
}

func scopeExcluded(cp Checkpoint, host string) bool {
	for _, ip := range cp.DNS[host] {
		addr, err := netip.ParseAddr(ip)
		if err == nil && !publicIP(addr) {
			return true
		}
	}
	return false
}
func coverageBlockers(cp Checkpoint) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, host := range cp.Blocked {
		if !scopeExcluded(cp, host) && !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}
func excludedHosts(cp Checkpoint) []string {
	out := []string{}
	for host := range cp.DNS {
		if scopeExcluded(cp, host) {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}
func coverageSummary(cp Checkpoint) string {
	parts := []string{}
	candidates, live := false, false
	for _, a := range cp.Assets {
		if a.Blocked {
			continue
		}
		if a.URL != "" {
			live = true
		}
		for _, port := range a.Ports {
			if webPort(strconv.Itoa(port)) {
				candidates = true
			}
		}
	}
	if candidates && !live {
		parts = append(parts, "HTTP probing recorded no live services on observed web ports; HTTP detection had no coverage.")
	}
	if len(cp.PortIncomplete) > 0 {
		parts = append(parts, fmt.Sprintf("Port checks remain incomplete for %d hosts; %d IPs fully checked. Resume scan to check remaining addresses.", len(cp.PortIncomplete), len(cp.PortResults)))
	}
	if len(cp.CrawlIncomplete) > 0 {
		parts = append(parts, fmt.Sprintf("Crawling remains incomplete for %d services; discoveries retained. Resume scan to continue unfinished seeds.", len(cp.CrawlIncomplete)))
	}
	if count := len(coverageBlockers(cp)); count > 0 {
		parts = append(parts, fmt.Sprintf("%d hosts had failed or incomplete coverage; see stage logs for details.", count))
	}
	if count := len(excludedHosts(cp)); count > 0 {
		parts = append(parts, fmt.Sprintf("%d non-public hosts were excluded by scope policy.", count))
	}
	return strings.Join(parts, " ") + " Unchecked findings are retained."
}
