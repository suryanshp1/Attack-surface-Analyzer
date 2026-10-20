package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/publicsuffix"
)

type Target struct {
	ID           string `json:"id"`
	Domain       string `json:"domain"`
	Status       string `json:"status"`
	Token        string `json:"token"`
	Schedule     string `json:"schedule"`
	LastScan     string `json:"lastScan"`
	Assets       int    `json:"assets"`
	Demo         bool   `json:"demo,omitempty"`
	LastVerified string `json:"lastVerified"`
	CanScan      bool   `json:"canScan"`
}
type Asset struct {
	ProbeStatus  string     `json:"probeStatus,omitempty"`
	Services     []Service  `json:"services"`
	Endpoints    []Endpoint `json:"endpoints"`
	ID           string     `json:"id"`
	Host         string     `json:"host"`
	Type         string     `json:"type"`
	IP           string     `json:"ip"`
	Status       int        `json:"status"`
	Technologies []string   `json:"technologies"`
	Ports        []int      `json:"ports"`
	Findings     int        `json:"findings"`
	Severity     string     `json:"severity"`
	FirstSeen    string     `json:"firstSeen"`
	LastSeen     string     `json:"lastSeen"`
	TLS          string     `json:"tls"`
	Source       string     `json:"source"`
	TargetID     string     `json:"targetId"`
	Title        string     `json:"title"`
	URL          string     `json:"url"`
	Removed      bool       `json:"removed"`
	MissingScans int        `json:"missingScans"`
	Blocked      bool       `json:"blocked"`
}
type Finding struct {
	ID           string   `json:"id"`
	DeletedAt    string   `json:"deletedAt,omitempty"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	Host         string   `json:"host"`
	Status       string   `json:"status"`
	Template     string   `json:"template"`
	FirstSeen    string   `json:"firstSeen"`
	LastSeen     string   `json:"lastSeen"`
	Description  string   `json:"description"`
	Remediation  string   `json:"remediation"`
	Evidence     string   `json:"evidence"`
	Notes        []Note   `json:"notes"`
	MatchedAt    string   `json:"matchedAt"`
	TargetID     string   `json:"targetId"`
	EvidenceKey  string   `json:"evidenceKey"`
	MissingScans int      `json:"missingScans"`
	Category     string   `json:"category,omitempty"`
	Port         int      `json:"port,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	Method       string   `json:"method,omitempty"`
	Parameters   []string `json:"parameters,omitempty"`
	StageName    string   `json:"stageName,omitempty"`
	Tool         string   `json:"tool,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	IP           string   `json:"ip,omitempty"`
	ScanID       string   `json:"scanId,omitempty"`
	StepLog      string   `json:"stepLog,omitempty"`
	StepSuccess  bool     `json:"stepSuccess,omitempty"`
}
type Note struct {
	Text  string `json:"text"`
	At    string `json:"at"`
	Actor string `json:"actor"`
}
type Stage struct {
	CoverageStatus string `json:"coverageStatus,omitempty"`
	Issue          string `json:"issue,omitempty"`
	StartedAt      string `json:"startedAt,omitempty"`
	FinishedAt     string `json:"finishedAt,omitempty"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	Tool           string `json:"tool"`
	Log            string `json:"log"`
	Attempts       int    `json:"attempts"`
}
type CheckCoverage struct {
	Finished  int `json:"finished"`
	Remaining int `json:"remaining"`
}
type ServiceIssue struct {
	Origin string `json:"origin"`
	Reason string `json:"reason"`
}
type ResumePlan struct {
	FromStage        string `json:"fromStage"`
	RetainedStages   int    `json:"retainedStages"`
	RepeatedStages   int    `json:"repeatedStages"`
	CheckpointPolicy string `json:"checkpointPolicy"`
}
type ScanCoverage struct {
	HTTP              *CheckCoverage `json:"http,omitempty"`
	Detection         *CheckCoverage `json:"detection,omitempty"`
	ServiceIssues     []ServiceIssue `json:"serviceIssues,omitempty"`
	ServiceIssueCount int            `json:"serviceIssueCount"`
	CrawlFinished     int            `json:"crawlFinished"`
	CrawlRemaining    int            `json:"crawlRemaining"`
	PortFinished      int            `json:"portFinished"`
	PortRemaining     int            `json:"portRemaining"`
}
type Scan struct {
	ParentScanID string       `json:"parentScanId,omitempty"`
	Resume       *ResumePlan  `json:"resume,omitempty"`
	Coverage     ScanCoverage `json:"coverage"`

	ExcludedHosts []string          `json:"excludedHosts,omitempty"`
	ID            string            `json:"id"`
	TargetID      string            `json:"targetId"`
	Domain        string            `json:"domain"`
	Status        string            `json:"status"`
	Trigger       string            `json:"trigger"`
	StartedAt     string            `json:"startedAt"`
	FinishedAt    string            `json:"finishedAt"`
	Progress      int               `json:"progress"`
	Stages        []Stage           `json:"stages"`
	Assets        int               `json:"assets"`
	Findings      int               `json:"findings"`
	Rate          int               `json:"rate"`
	Demo          bool              `json:"demo,omitempty"`
	Error         string            `json:"error"`
	Worker        string            `json:"worker"`
	Lease         string            `json:"lease,omitempty"`
	LeaseUntil    string            `json:"leaseUntil,omitempty"`
	Attempts      int               `json:"attempts"`
	Concurrency   int               `json:"concurrency"`
	Checkpoint    Checkpoint        `json:"checkpoint,omitempty"`
	RetryAt       string            `json:"retryAt,omitempty"`
	ToolVersions  map[string]string `json:"toolVersions"`
	TemplateSet   string            `json:"templateSet"`
}
type Event struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
}
type Settings struct {
	Name        string `json:"name"`
	Rate        int    `json:"rate"`
	Concurrency int    `json:"concurrency"`
	Retention   int    `json:"retention"`
	Paused      bool   `json:"paused"`
}
type MXRecord struct {
	Host string   `json:"host"`
	Pref int      `json:"pref"`
	IPs  []string `json:"ips,omitempty"`
}
type DomainDNSPosture struct {
	ID           string     `json:"id"`
	ScanID       string     `json:"scanId"`
	Domain       string     `json:"domain"`
	SPFRecord    string     `json:"spfRecord"`
	SPFStatus    string     `json:"spfStatus"` // 'secure', 'softfail', 'permissive', 'missing'
	DMARCRecord  string     `json:"dmarcRecord"`
	DMARCPolicy  string     `json:"dmarcPolicy"` // 'reject', 'quarantine', 'none', 'missing'
	DKIMDetected bool       `json:"dkimDetected"`
	MXRecords    []MXRecord `json:"mxRecords"`
	CreatedAt    string     `json:"createdAt"`
}
type SubdomainTakeover struct {
	ID              string `json:"id"`
	ScanID          string `json:"scanId"`
	Subdomain       string `json:"subdomain"`
	CNAME           string `json:"cname"`
	ServiceProvider string `json:"serviceProvider"`
	Status          string `json:"status"` // 'open', 'resolved', 'suppressed'
	FirstSeen       string `json:"firstSeen"`
	LastSeen        string `json:"lastSeen"`
	ReopenCount     int    `json:"reopenCount"`
	MissingScans    int    `json:"missingScans"`
}
type EndpointHazard struct {
	ID          string `json:"id"`
	ScanID      string `json:"scanId"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	HazardClass string `json:"hazardClass"` // 'ssrf_candidate', 'redirect_candidate', 'lfi_candidate', 'sqli_candidate', 'debug_flag', 'sensitive_file'
	Severity    string `json:"severity"`    // 'critical', 'high', 'medium', 'low'
	CreatedAt   string `json:"createdAt"`
}
type NotificationWebhook struct {
	ID                   string `json:"id"`
	URL                  string `json:"url"`
	WebhookType          string `json:"webhookType"` // 'slack', 'discord', 'generic'
	Enabled              bool   `json:"enabled"`
	NotifyOnNewAssets    bool   `json:"notifyOnNewAssets"`
	NotifyOnNewPorts     bool   `json:"notifyOnNewPorts"`
	NotifyOnHighFindings bool   `json:"notifyOnHighFindings"`
	NotifyOnTakeovers    bool   `json:"notifyOnTakeovers"`
	CreatedAt            string `json:"createdAt"`
}
type State struct {
	RecordDeletions map[string]string     `json:"recordDeletions,omitempty"`
	Members         []Member              `json:"members"`
	AccessKeys      []AccessKey           `json:"accessKeys"`
	Me              Actor                 `json:"me"`
	History         []Endpoint            `json:"history"`
	Targets         []Target              `json:"targets"`
	Assets          []Asset               `json:"assets"`
	Findings        []Finding             `json:"findings"`
	Scans           []Scan                `json:"scans"`
	Events          []Event               `json:"events"`
	Audit           []Event               `json:"audit"`
	Settings        Settings              `json:"settings"`
	Demo            bool                  `json:"demo,omitempty"`
	Runtime         RuntimeInfo           `json:"runtime"`
	DNSPosture      []DomainDNSPosture    `json:"dnsPosture,omitempty"`
	Takeovers       []SubdomainTakeover   `json:"takeovers,omitempty"`
	Hazards         []EndpointHazard      `json:"hazards,omitempty"`
	Webhooks        []NotificationWebhook `json:"webhooks,omitempty"`
}
type Server struct {
	mu              sync.Mutex
	state           State
	file            string
	db              *pgxpool.Pool
	ctx             context.Context
	lookupTXT       func(context.Context, string) ([]string, error)
	liveEnabled     bool
	allowUnverified bool
	workers         map[string]WorkerInfo
	evidence        *EvidenceStore
	gatewaySecret   string
	persisted       map[string]string
	requestActor    string
	mcpOnce         sync.Once
	mcpHandler      http.Handler
	changeCh        chan struct{}
}

func (s *Server) changeChannel() chan struct{} {
	if s.changeCh == nil {
		s.changeCh = make(chan struct{})
	}
	return s.changeCh
}

func (s *Server) broadcast() {
	if s.changeCh != nil {
		close(s.changeCh)
	}
	s.changeCh = make(chan struct{})
}

func id() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func now() string { return time.Now().UTC().Format(time.RFC3339) }
func (s *Server) audit(action, detail string) {
	actor := s.requestActor
	if actor == "" {
		actor = "Workspace owner"
	}
	s.auditActor(action, detail, actor)
}
func (s *Server) auditActor(action, detail, actor string) {
	s.state.Audit = append([]Event{{id(), "audit", action, detail, now(), actor}}, s.state.Audit...)
}
func (s *Server) save() error {
	if s.db != nil {
		if err := s.saveRelational(); err != nil {
			return err
		}
		s.broadcast()
		return nil
	}
	b, err := json.Marshal(s.state)
	if err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(s.file), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(s.file+".tmp", b, 0600); err != nil {
		return err
	}
	if err = os.Rename(s.file+".tmp", s.file); err != nil {
		return err
	}
	s.broadcast()
	return nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "Invalid request payload")
		return false
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		fail(w, 400, "Request must contain one JSON object")
		return false
	}
	return true
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func validDomain(d string) bool {
	if len(d) > 253 || !domainPattern.MatchString(d) || net.ParseIP(d) != nil {
		return false
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil || root != d {
		return false
	}
	for _, p := range []string{"github.io", "vercel.app", "netlify.app", "pages.dev", "blogspot.com", "amazonaws.com", "azurewebsites.net", "herokuapp.com"} {
		if d == p || strings.HasSuffix(d, "."+p) {
			return false
		}
	}
	return true
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (s *Server) observabilityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = id()
		}
		w.Header().Set("X-Request-ID", reqID)
		ctx := WithRequestID(r.Context(), reqID)
		r = r.WithContext(ctx)

		GlobalTelemetry.IncInflight()
		defer GlobalTelemetry.DecInflight()

		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)

		dur := time.Since(start)
		GlobalTelemetry.RecordRequest(r.Method, r.URL.Path, rec.status, dur)

		if r.URL.Path != "/health" {
			Log(ctx).Info("http_request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", dur.Milliseconds(),
				"bytes", rec.bytes,
			)
		}
	})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	reqID := RequestIDFromContext(r.Context())
	if reqID == "" {
		reqID = r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = id()
		}
		r = r.WithContext(WithRequestID(r.Context(), reqID))
	}
	w.Header().Set("X-Request-ID", reqID)
	if r.URL.Path == "/api/mcp" {
		s.serveMCP(w, r)
		return
	}
	if r.URL.Path == "/health" {
		respond(w, 200, map[string]string{"status": "ok"})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/internal/") {
		s.workerAPI(w, r)
		return
	}
	if r.URL.Path == "/api/health" {
		s.health(w, r)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			fail(w, 403, "Cross-origin requests are not allowed")
			return
		}
	}
	actor, authorized := s.actor(r)
	if !authorized {
		fail(w, 401, "Unauthorized")
		return
	}
	pathForRole := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	if r.Method != "GET" && !canWrite(actor, pathForRole) {
		fail(w, 403, "Your role cannot perform this action")
		return
	}
	if r.URL.Path == "/api/events" && r.Method == "GET" {
		s.stream(w, r)
		return
	}
	if pathForRole == "webhooks/test" && r.Method == "POST" {
		s.testWebhook(w, r)
		return
	}
	if pathForRole == "reports.pdf" && r.Method == "GET" {
		s.mu.Lock()
		actor, authorized = s.actorLocked(r)
		snapshot := s.publicStateFor(actor)
		s.mu.Unlock()
		if !authorized {
			fail(w, 401, "Unauthorized")
			return
		}
		reportPDF(w, r, snapshot)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, authorized = s.actorLocked(r)
	if !authorized {
		fail(w, 401, "Unauthorized")
		return
	}
	if r.Method != "GET" && !canWrite(actor, pathForRole) {
		fail(w, 403, "Your role cannot perform this action")
		return
	}
	s.requestActor = actor.Name
	defer func() { s.requestActor = "" }()
	before, _ := json.Marshal(s.state)
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	parts := strings.Split(path, "/")
	if path == "metrics" && r.Method == "GET" {
		s.metrics(w, r, actor)
		return
	}
	if path == "state" && r.Method == "GET" {
		respond(w, 200, s.publicStateFor(actor))
		return
	}
	if s.accessAPI(w, r, path, actor) {
		return
	}
	mutated := false
	var result any
	status := 200
	switch {
	case path == "targets" && r.Method == "POST":
		var p struct {
			Domain string `json:"domain"`
		}
		if !decode(w, r, &p) {
			return
		}
		d := strings.ToLower(strings.TrimSpace(p.Domain))
		if !validDomain(d) {
			fail(w, 400, "Enter a root domain, such as company.com. Public suffixes, IPs and shared hosting domains are not allowed.")
			return
		}
		for _, t := range s.state.Targets {
			if t.Domain == d {
				fail(w, 409, "This domain is already in your workspace")
				return
			}
		}
		t := Target{ID: id(), Domain: d, Status: "pending", Token: "surfacer-verification=" + id(), Schedule: "Manual", Demo: false}
		s.state.Targets = append(s.state.Targets, t)
		s.audit("Target added", d)
		result = t
		mutated = true
		status = 201
	case len(parts) == 3 && parts[0] == "targets" && parts[2] == "verify" && r.Method == "POST":
		index := -1
		for i, t := range s.state.Targets {
			if t.ID == parts[1] {
				index = i
			}
		}
		if index < 0 {
			fail(w, 404, "Target not found")
			return
		}
		t := s.state.Targets[index]
		if t.Demo {
			fail(w, 400, "Legacy sample targets cannot be verified; add a domain you own.")
			return
		}
		err := s.verifyTarget(r.Context(), &t)
		if errors.Is(err, errDNSUnavailable) {
			fail(w, 503, err.Error())
			return
		}
		if err != nil {
			if t.Status == "verified" && !s.allowUnverified {
				s.state.Targets[index].Status = "paused"
				for j, scan := range s.state.Scans {
					if scan.TargetID == t.ID && activeScan(scan.Status) {
						s.state.Scans[j].Status = "canceled"
						s.state.Scans[j].FinishedAt = now()
						s.state.Scans[j].Error = "Ownership proof no longer matches"
					}
				}
			}
			if s.allowUnverified {
				s.state.Targets[index].Status = "pending"
			}
			s.audit("Verification failed", t.Domain)
			if err := s.save(); err != nil {
				fail(w, 500, "Could not persist verification result")
				return
			}
			fail(w, 422, err.Error())
			return
		}
		s.state.Targets[index].Status = "verified"
		s.state.Targets[index].LastVerified = now()
		s.audit("Ownership verified", t.Domain)
		result = s.state.Targets[index]
		mutated = true
	case len(parts) == 2 && parts[0] == "targets" && r.Method == "PATCH":
		var p struct {
			Schedule string `json:"schedule"`
		}
		if !decode(w, r, &p) {
			return
		}
		if p.Schedule != "Daily" && p.Schedule != "Weekly" && p.Schedule != "Manual" {
			fail(w, 400, "Schedule must be Daily, Weekly or Manual")
			return
		}
		found := false
		for i, t := range s.state.Targets {
			if t.ID == parts[1] {
				if p.Schedule != "Manual" && !s.liveEnabled {
					fail(w, 409, "Active scanner deployment is not configured; automated live scans are disabled.")
					return
				}
				s.state.Targets[i].Schedule = p.Schedule
				result = s.state.Targets[i]
				s.audit("Schedule updated", t.Domain+": "+p.Schedule)
				found = true
			}
		}
		if !found {
			fail(w, 404, "Target not found")
			return
		}
		mutated = true
	case path == "scans" && r.Method == "POST":
		var p struct {
			TargetID string `json:"targetId"`
		}
		if !decode(w, r, &p) {
			return
		}
		var target *Target
		for i, t := range s.state.Targets {
			if t.ID == p.TargetID {
				target = &s.state.Targets[i]
			}
		}
		if target == nil {
			fail(w, 404, "Target not found")
			return
		}
		if s.state.Settings.Paused {
			fail(w, 409, "Workspace scanning is paused. Resume it in Settings.")
			return
		}
		if !s.targetCanScan(target) {
			fail(w, 403, "Ownership must be verified before scanning")
			return
		}
		{
			if !s.liveEnabled {
				fail(w, 503, "Start the Docker Compose worker stack to enable live scanning.")
				return
			}
			if err := s.checkScanOwnership(r.Context(), target); err != nil {
				target.Status = "paused"
				s.audit("Scan blocked: ownership proof missing", target.Domain)
				_ = s.save()
				fail(w, 403, err.Error())
				return
			}
		}
		for _, sc := range s.state.Scans {
			if sc.TargetID == target.ID && activeScan(sc.Status) {
				fail(w, 409, "A scan is already running for this domain")
				return
			}
		}
		scan := s.makeScan(*target, "Manual")
		s.state.Scans = append([]Scan{scan}, s.state.Scans...)
		s.audit("Scan queued", target.Domain+" · rate "+fmt.Sprint(scan.Rate)+" req/s")
		result = scan
		mutated = true
		status = 201
	case len(parts) == 3 && parts[0] == "scans" && parts[2] == "retry" && r.Method == "POST":
		if s.state.Settings.Paused || !s.liveEnabled {
			fail(w, 409, "Scanning is paused or unavailable")
			return
		}
		var previous *Scan
		for i := range s.state.Scans {
			if s.state.Scans[i].ID == parts[1] && !s.recordDeleted("scans", parts[1]) {
				previous = &s.state.Scans[i]
				break
			}
		}
		if previous == nil {
			fail(w, 404, "Scan not found")
			return
		}
		if previous.Status != "partial" && previous.Status != "failed" {
			fail(w, 409, "Only failed or partial scans can be resumed")
			return
		}
		var target *Target
		for i := range s.state.Targets {
			if s.state.Targets[i].ID == previous.TargetID {
				target = &s.state.Targets[i]
				break
			}
		}
		if !s.targetCanScan(target) {
			fail(w, 403, "Target is not scan-ready")
			return
		}
		if err := s.checkScanOwnership(r.Context(), target); err != nil {
			fail(w, 403, err.Error())
			return
		}
		for _, active := range s.state.Scans {
			if active.TargetID == previous.TargetID && (active.Status == "queued" || active.Status == "running" || active.Status == "retrying") {
				fail(w, 409, "Target already has an active scan")
				return
			}
		}
		previousID := previous.ID
		var retry Scan
		raw, _ := json.Marshal(previous)
		_ = json.Unmarshal(raw, &retry)
		retry.ID = id()
		retry.Status = "queued"
		retry.Trigger = "Retry"
		retry.StartedAt = now()
		retry.FinishedAt = ""
		retry.Error = ""
		retry.Lease = ""
		retry.LeaseUntil = ""
		retry.Worker = ""
		retry.Attempts = 0
		retry.RetryAt = ""
		firstPending := resumeStage(retry)
		retry.Progress = firstPending * 100 / max(1, len(retry.Stages))
		retry.ParentScanID = previousID
		retry.Resume = nil
		for i := firstPending; i < len(retry.Stages); i++ {
			retry.Stages[i].Status = "pending"
		}
		if firstPending < len(retry.Stages) && (retry.Stages[firstPending].Name == "Discovery" || retry.Stages[firstPending].Name == "DNS resolution") {
			retry.Checkpoint = Checkpoint{Known: retry.Checkpoint.Known, KnownSecrets: retry.Checkpoint.KnownSecrets, Hosts: retry.Checkpoint.Hosts, IncompleteStages: retry.Checkpoint.IncompleteStages}
		}
		if firstPending < len(retry.Stages) && (retry.Stages[firstPending].Name == "Port discovery" || retry.Stages[firstPending].Name == "HTTP probing") {
			retry.Checkpoint = resumeNetworkCheckpoint(retry.Checkpoint)
		}
		for i := range retry.Stages {
			if retry.Stages[i].Status != "completed" {
				retry.Stages[i].Status = "pending"
				retry.Stages[i].Attempts = 0
				retry.Stages[i].Log = ""
				retry.Stages[i].StartedAt = ""
				retry.Stages[i].FinishedAt = ""
				retry.Stages[i].CoverageStatus = ""
				retry.Stages[i].Issue = ""
			}
		}
		s.state.Scans = append([]Scan{retry}, s.state.Scans...)
		s.audit("Partial scan resumed", target.Domain+" · prior scan "+previousID)
		result = retry
		mutated = true
	case len(parts) == 3 && parts[0] == "scans" && parts[2] == "cancel" && r.Method == "POST":
		found := false
		for i, sc := range s.state.Scans {
			if sc.ID == parts[1] {
				if !activeScan(sc.Status) {
					fail(w, 409, "Only active scans can be canceled")
					return
				}
				s.state.Scans[i].Status = "canceled"
				s.state.Scans[i].FinishedAt = now()
				for j, st := range sc.Stages {
					if st.Status == "running" || st.Status == "pending" {
						s.state.Scans[i].Stages[j].Status = "canceled"
					}
				}
				s.audit("Scan canceled", sc.Domain)
				result = s.state.Scans[i]
				found = true
			}
		}
		if !found {
			fail(w, 404, "Scan not found")
			return
		}
		mutated = true
	case (len(parts) == 1 || len(parts) == 2) && deletableResource(parts[0]) && r.Method == "DELETE":
		if actor.Role != "owner" {
			fail(w, 403, "Only workspace owners can delete records")
			return
		}
		var p struct {
			IDs []string `json:"ids"`
		}
		if len(parts) == 2 {
			p.IDs = []string{parts[1]}
		} else if !decode(w, r, &p) {
			return
		}
		deleted, err := s.deleteRecords(parts[0], p.IDs)
		if err != nil {
			code := 400
			if errors.Is(err, errActiveScanDeletion) {
				code = 409
			}
			fail(w, code, err.Error())
			return
		}
		result = map[string]any{"deleted": deleted}
		mutated = deleted > 0
	case len(parts) == 2 && parts[0] == "findings" && r.Method == "PATCH":
		var p struct {
			Status string `json:"status"`
			Note   string `json:"note"`
		}
		if !decode(w, r, &p) {
			return
		}
		if p.Status != "open" && p.Status != "accepted risk" && p.Status != "false positive" {
			fail(w, 400, "Choose open, accepted risk or false positive. Resolution requires successful scanner coverage.")
			return
		}
		if len(strings.TrimSpace(p.Note)) < 3 || len(p.Note) > 2000 {
			fail(w, 400, "Add a note between 3 and 2,000 characters")
			return
		}
		found := false
		for i, f := range s.state.Findings {
			if f.ID == parts[1] && f.DeletedAt == "" {
				s.state.Findings[i].Status = p.Status
				s.state.Findings[i].Notes = append(s.state.Findings[i].Notes, Note{p.Note, now(), actor.Name})
				s.audit("Finding triaged", f.Title+": "+p.Status)
				result = s.state.Findings[i]
				found = true
			}
		}
		if !found {
			fail(w, 404, "Finding not found")
			return
		}
		mutated = true
	case path == "settings" && r.Method == "PATCH":
		var p Settings
		if !decode(w, r, &p) {
			return
		}
		if len(strings.TrimSpace(p.Name)) < 2 || len(p.Name) > 60 || p.Rate < 1 || p.Rate > 30 || p.Concurrency < 1 || p.Concurrency > 10 || p.Retention < 1 || p.Retention > 365 {
			fail(w, 400, "Name is required. Rate: 1–30, concurrency: 1–10, retention: 1–365.")
			return
		}
		s.state.Settings = p
		if p.Paused {
			for i, sc := range s.state.Scans {
				if activeScan(sc.Status) {
					s.state.Scans[i].Status = "canceled"
					s.state.Scans[i].FinishedAt = now()
					for j, st := range sc.Stages {
						if st.Status != "completed" {
							s.state.Scans[i].Stages[j].Status = "canceled"
						}
					}
				}
			}
		}
		s.audit("Workspace settings updated", fmt.Sprintf("Rate %d · concurrency %d · paused %t", p.Rate, p.Concurrency, p.Paused))
		result = p
		mutated = true
	case path == "webhooks" && r.Method == "GET":
		result = publicWebhooks(s.state.Webhooks)
	case path == "webhooks" && r.Method == "POST":
		var p struct {
			URL                  string `json:"url"`
			WebhookType          string `json:"webhookType"`
			Enabled              *bool  `json:"enabled"`
			NotifyOnNewAssets    *bool  `json:"notifyOnNewAssets"`
			NotifyOnNewPorts     *bool  `json:"notifyOnNewPorts"`
			NotifyOnHighFindings *bool  `json:"notifyOnHighFindings"`
			NotifyOnTakeovers    *bool  `json:"notifyOnTakeovers"`
		}
		if !decode(w, r, &p) {
			return
		}
		if err := validateWebhookURL(p.URL); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if len(s.state.Webhooks) >= 32 {
			fail(w, 409, "Webhook limit reached")
			return
		}
		whType := strings.ToLower(strings.TrimSpace(p.WebhookType))
		if whType != "slack" && whType != "discord" && whType != "generic" {
			whType = "generic"
		}
		enabled := true
		if p.Enabled != nil {
			enabled = *p.Enabled
		}
		newAssets := true
		if p.NotifyOnNewAssets != nil {
			newAssets = *p.NotifyOnNewAssets
		}
		newPorts := true
		if p.NotifyOnNewPorts != nil {
			newPorts = *p.NotifyOnNewPorts
		}
		highFindings := true
		if p.NotifyOnHighFindings != nil {
			highFindings = *p.NotifyOnHighFindings
		}
		takeovers := true
		if p.NotifyOnTakeovers != nil {
			takeovers = *p.NotifyOnTakeovers
		}
		wh := NotificationWebhook{
			ID:                   id(),
			URL:                  p.URL,
			WebhookType:          whType,
			Enabled:              enabled,
			NotifyOnNewAssets:    newAssets,
			NotifyOnNewPorts:     newPorts,
			NotifyOnHighFindings: highFindings,
			NotifyOnTakeovers:    takeovers,
			CreatedAt:            now(),
		}
		s.state.Webhooks = append([]NotificationWebhook{wh}, s.state.Webhooks...)
		s.audit("Webhook created", wh.WebhookType+" · "+wh.ID)
		result = publicWebhooks([]NotificationWebhook{wh})[0]
		status = 201
		mutated = true
	case path == "webhooks" && r.Method == "DELETE":
		whID := r.URL.Query().Get("id")
		if whID == "" {
			fail(w, 400, "Webhook id is required")
			return
		}
		found := false
		var remaining []NotificationWebhook
		for _, wh := range s.state.Webhooks {
			if wh.ID == whID {
				found = true
			} else {
				remaining = append(remaining, wh)
			}
		}
		if !found {
			fail(w, 404, "Webhook not found")
			return
		}
		s.state.Webhooks = remaining
		s.audit("Webhook deleted", whID)
		result = map[string]bool{"ok": true}
		mutated = true
	case len(parts) == 2 && parts[0] == "takeovers" && r.Method == "PATCH":
		var p struct {
			Status string `json:"status"`
		}
		if !decode(w, r, &p) {
			return
		}
		if p.Status != "open" && p.Status != "suppressed" && p.Status != "resolved" {
			fail(w, 400, "Status must be open, suppressed, or resolved")
			return
		}
		found := false
		for i, to := range s.state.Takeovers {
			if to.ID == parts[1] && !s.recordDeleted("takeovers", to.ID) {
				s.state.Takeovers[i].Status = p.Status
				s.audit("Subdomain takeover status updated", to.Subdomain+": "+p.Status)
				result = s.state.Takeovers[i]
				found = true
				break
			}
		}
		if !found {
			fail(w, 404, "Subdomain takeover not found")
			return
		}
		mutated = true
	default:
		fail(w, 404, "Endpoint not found")
		return
	}
	if mutated {
		if err := s.save(); err != nil {
			var restored State
			if json.Unmarshal(before, &restored) == nil {
				s.state = restored
			}
			log.Printf("persist: %v", err)
			fail(w, 500, "Could not save changes. Please retry.")
			return
		}
	}
	respond(w, status, result)
}
func newScan(t Target, trigger string, rate int) Scan {
	sc := Scan{ToolVersions: toolVersions, TemplateSet: "v10.5.0-curated-2", ID: id(), TargetID: t.ID, Domain: t.Domain, Status: "queued", Trigger: trigger, StartedAt: now(), Rate: rate, Concurrency: 5}
	tools := []string{"subfinder", "dnsx", "naabu", "httpx", "tlsx", "Go TLS", "gau", "katana", "gitleaks", "nuclei", "Surfacer", "Surfacer"}
	names := []string{"Discovery", "DNS resolution", "Port discovery", "HTTP probing", "TLS assessment", "TLS inspection", "Historical discovery", "Endpoint crawling", "JavaScript secrets", "Detection", "Normalization", "Change detection"}
	for i, name := range names {
		tool := tools[i]
		if version := toolVersions[tool]; version != "" {
			tool += " " + version
		}
		status := "pending"
		sc.Stages = append(sc.Stages, Stage{Name: name, Status: status, Tool: tool})
	}
	return sc
}
func (s *Server) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirty := false
	for _, t := range s.state.Targets {
		if !s.targetCanScan(&t) || t.Schedule == "Manual" || s.state.Settings.Paused {
			continue
		}
		interval := 24 * time.Hour
		if t.Schedule == "Weekly" {
			interval *= 7
		}
		last, err := time.Parse(time.RFC3339, t.LastScan)
		if err != nil {
			last = time.Time{}
		}
		for _, previous := range s.state.Scans {
			if previous.TargetID == t.ID {
				started, e := time.Parse(time.RFC3339, previous.StartedAt)
				if e == nil && started.After(last) {
					last = started
				}
			}
		}
		if time.Since(last) < interval {
			continue
		}
		running := false
		for _, sc := range s.state.Scans {
			if sc.TargetID == t.ID && activeScan(sc.Status) {
				running = true
			}
		}
		if !running {
			if !s.liveEnabled {
				continue
			}
			s.state.Scans = append([]Scan{s.makeScan(t, "Scheduled")}, s.state.Scans...)
			s.audit("Scheduled scan queued", t.Domain)
			dirty = true
		}
	}
	if dirty {
		if err := s.save(); err != nil {
			log.Printf("persist scan progress: %v", err)
		}
	}
}
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, "Streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previous []byte
	lastSent := time.Time{}
	for {
		s.mu.Lock()
		actor, ok := s.actorLocked(r)
		if !ok {
			s.mu.Unlock()
			return
		}
		b, _ := json.Marshal(s.publicStateFor(actor))
		ch := s.changeChannel()
		s.mu.Unlock()
		if !bytes.Equal(previous, b) {
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			previous = b
			lastSent = time.Now()
			f.Flush()
		} else if time.Since(lastSent) >= 15*time.Second {
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			lastSent = time.Now()
			f.Flush()
		}
		var serverCtxDone <-chan struct{}
		if s.ctx != nil {
			serverCtxDone = s.ctx.Done()
		}
		select {
		case <-r.Context().Done():
			return
		case <-serverCtxDone:
			return
		case <-ch:
		case <-ticker.C:
		}
	}
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrations()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		res, err := http.Get("http://127.0.0.1:8080/health")
		if err != nil || res.StatusCode != 200 {
			os.Exit(1)
		}
		res.Body.Close()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		runWorker()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "gateway" {
		runGateway()
		return
	}
	InitLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	file := os.Getenv("DATA_FILE")
	if file == "" {
		file = "data/workspace.json"
	}
	s := &Server{allowUnverified: os.Getenv("REQUIRE_DNS_VERIFICATION") != "true", file: file, ctx: ctx, liveEnabled: os.Getenv("LIVE_SCANNING") == "true", workers: map[string]WorkerInfo{}, gatewaySecret: os.Getenv("EGRESS_SECRET")}
	s.state = emptyState()
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		db, err := pgxpool.New(ctx, dsn)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		s.db = db
		if err = s.migrateAndLoad(); err != nil {
			log.Fatal(err)
		}
	} else if b, err := os.ReadFile(file); err == nil {
		if err = json.Unmarshal(b, &s.state); err != nil {
			log.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	s.state.removeLegacySamples()
	for i, sc := range s.state.Scans {
		if activeScan(sc.Status) {
			if sc.Demo {
				s.state.Scans[i].Status = "canceled"
				s.state.Scans[i].FinishedAt = now()
			} else {
				s.state.Scans[i].Status = "queued"
				s.state.Scans[i].Lease = ""
				s.state.Scans[i].Worker = ""
				for j := range s.state.Scans[i].Stages {
					if s.state.Scans[i].Stages[j].Status == "running" {
						s.state.Scans[i].Stages[j].Status = "pending"
					}
				}
			}
			s.audit("Interrupted scan recovered", sc.Domain)
		}
	}
	if s.liveEnabled && (s.db == nil || os.Getenv("WORKER_TOKEN") == "" || s.gatewaySecret == "") {
		log.Fatal("Live scanning requires PostgreSQL, WORKER_TOKEN and EGRESS_SECRET")
	}
	if err := s.initEvidence(); err != nil {
		log.Fatal(err)
	}
	if err := s.save(); err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") && os.Getenv("API_TOKEN") == "" {
		log.Fatal("API_TOKEN is required when listening outside loopback")
	}
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reverifyOwnedTargets()
				s.cleanupEvidence()
			}
		}
	}()
	srv := &http.Server{Addr: addr, Handler: s.observabilityMiddleware(http.HandlerFunc(s.handle)), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.tick()
				s.maintenance()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(c)
	}()
	log.Printf("Surfacer API listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
