package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	URL               string   `json:"url"`
	Port              int      `json:"port"`
	Status            int      `json:"status"`
	Title             string   `json:"title"`
	Technologies      []string `json:"technologies"`
	TLSVersion        string   `json:"tlsVersion,omitempty"`
	Cipher            string   `json:"cipher,omitempty"`
	CertificateExpiry string   `json:"certificateExpiry,omitempty"`
	CertificateNames  []string `json:"certificateNames,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	SelfSigned        bool     `json:"selfSigned,omitempty"`
	Mismatched        bool     `json:"mismatched,omitempty"`
	Untrusted         bool     `json:"untrusted,omitempty"`
}

const portBatchSize = 5

// PortResults contains an entry (including an empty list) only for fully checked IPs.
// Completed batches survive worker replacement and never need to be rescanned.
func portTargets(cp Checkpoint) []string {
	seen := map[string]bool{}
	ips := []string{}
	for _, a := range cp.Assets {
		if a.Blocked {
			continue
		}
		for _, ip := range cp.DNS[a.Host] {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	sort.Strings(ips)
	return ips
}
func portStageTimeout(cp Checkpoint, rate int) time.Duration {
	// Account for the rate ceiling and three seconds per connect at concurrency five.
	remaining := 0
	for _, ip := range portTargets(cp) {
		if _, done := cp.PortResults[ip]; !done {
			remaining++
		}
	}
	checks := remaining * len(commonPorts)
	estimated := time.Duration(checks)*max(time.Second/time.Duration(min(max(rate, 1), 10)), 600*time.Millisecond) + time.Minute
	return min(max(7*time.Minute, estimated), 40*time.Minute)
}
func (w *Worker) scanPorts(ctx context.Context, c Claim, cp Checkpoint, dir string) (Checkpoint, string, error) {
	cp.PortIncomplete = nil
	ips := portTargets(cp)
	if len(ips) == 0 {
		return cp, "No public addresses available for port discovery.", nil
	}
	if cp.PortResults == nil {
		cp.PortResults = map[string][]int{}
	}
	pending := []string{}
	for _, ip := range ips {
		if _, done := cp.PortResults[ip]; !done {
			pending = append(pending, ip)
		}
	}
	proxyHost, err := urlParseProxy(c.Proxy)
	if err != nil {
		return cp, "", err
	}
	logs := []string{}
	incomplete := false
	rate := min(max(c.Scan.Rate, 1), 10)
	checkBudget := max(time.Second/time.Duration(rate), 600*time.Millisecond)
	batchSize := min(portBatchSize, max(1, int((150*time.Second)/checkBudget)/len(commonPorts)))
	for offset := 0; offset < len(pending); offset += batchSize {
		batch := pending[offset:min(offset+batchSize, len(pending))]
		input, e := writeList(dir, "port-targets.txt", batch)
		if e != nil {
			return cp, "", e
		}
		batchCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		runner := command
		if w.scannerCommand != nil {
			runner = w.scannerCommand
		}
		out, logText, runErr := runner(batchCtx, "naabu", []string{"-l", input, "-p", strings.Join(intStrings(commonPorts), ","), "-s", "c", "-proxy", net.JoinHostPort(proxyHost, "1080"), "-proxy-auth", c.Scan.ID + ":" + c.Scan.Lease, "-rate", strconv.Itoa(min(max(1, c.Scan.Rate), 10)), "-c", "5", "-retries", "1", "-timeout", "3000", "-json", "-silent", "-duc", "-no-stdin"}, "", dir)
		timedOut := batchCtx.Err() != nil
		cancel()
		if strings.TrimSpace(logText) != "" {
			logs = append(logs, logText)
		}
		found := map[string][]int{}
		parseErr := jsonLines(out, func(b []byte) error {
			var row struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}
			if e := json.Unmarshal(b, &row); e != nil {
				return e
			}
			if contains(batch, row.IP) && scanPort(row.Port) && !contains(intStrings(found[row.IP]), strconv.Itoa(row.Port)) {
				found[row.IP] = append(found[row.IP], row.Port)
			}
			return nil
		})
		if parseErr != nil {
			return cp, strings.Join(logs, "\n"), parseErr
		}
		for i := range cp.Assets {
			a := &cp.Assets[i]
			for _, ip := range cp.DNS[a.Host] {
				for _, port := range found[ip] {
					if !contains(intStrings(a.Ports), strconv.Itoa(port)) {
						a.Ports = append(a.Ports, port)
					}
				}
			}
			sort.Ints(a.Ports)
		}
		if runErr == nil {
			for _, ip := range batch {
				ports := found[ip]
				if ports == nil {
					ports = []int{}
				}
				sort.Ints(ports)
				cp.PortResults[ip] = ports
			}
		}
		if runErr != nil && !timedOut {
			return cp, strings.Join(logs, "\n"), runErr
		}
		if timedOut {
			incomplete = true
		}
		// Persist every finished batch before starting another. The same lease and stage order apply.
		if w.API != "" {
			stage := -1
			for i, st := range c.Scan.Stages {
				if st.Name == "Port discovery" {
					stage = i
					break
				}
			}
			if stage >= 0 {
				payload := w.payload(c.Scan)
				payload["stage"] = stage
				payload["status"] = "progress"
				payload["checkpoint"] = cp
				payload["log"] = fmt.Sprintf("Naabu: %d/%d addresses fully checked; %d ports/address; rate <= %d/s.", len(cp.PortResults), len(ips), len(commonPorts), min(max(c.Scan.Rate, 1), 10))
				commitCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				e = w.call(commitCtx, "/internal/stage", payload, nil)
				stop()
				if e != nil {
					return cp, "", e
				}
			}
		}
		if ctx.Err() != nil {
			incomplete = true
			break
		}
	}
	if incomplete || len(cp.PortResults) < len(ips) {
		issue := fmt.Sprintf("Port coverage incomplete: %d/%d addresses fully checked within bounded batch/stage budgets. Observed open ports retained; unchecked ports are not closed.", len(cp.PortResults), len(ips))
		cp.SourceIssues = append(cp.SourceIssues, issue)
		logs = append(logs, issue)
		for _, a := range cp.Assets {
			for _, ip := range cp.DNS[a.Host] {
				if _, done := cp.PortResults[ip]; !done {
					cp.PortIncomplete = append(cp.PortIncomplete, a.Host)
					break
				}
			}
		}
	}
	count := 0
	for _, a := range cp.Assets {
		count += len(a.Ports)
	}
	return cp, fmt.Sprintf("Naabu TCP-connect: %d observed open ports; %d/%d addresses fully checked; %d explicit ports. %s", count, len(cp.PortResults), len(ips), len(commonPorts), strings.Join(logs, "\n")), nil
}
func (w *Worker) assessTLS(ctx context.Context, c Claim, cp Checkpoint, dir string) (Checkpoint, string, error) {
	targets := []string{}
	for _, a := range cp.Assets {
		if a.Blocked {
			continue
		}
		for _, port := range a.Ports {
			if port == 443 || port == 8443 || port == 9443 || port == 2376 {
				targets = append(targets, net.JoinHostPort(a.Host, strconv.Itoa(port)))
			}
		}
	}
	if len(targets) == 0 {
		return cp, "No observed TLS ports available for TLSx.", nil
	}
	input, err := writeList(dir, "tls-targets.txt", targets)
	if err != nil {
		return cp, "", err
	}
	out, logs, err := command(ctx, "tlsx", []string{"-l", input, "-json", "-silent", "-duc", "-sm", "ctls", "-r", c.DNS, "-proxy", socksProxy(c), "-c", "2", "-timeout", "8", "-retry", "0", "-delay", "500ms", "-tv", "-cipher", "-ex", "-ss", "-mm", "-un"}, "", dir)
	if err != nil {
		return cp, logs, err
	}
	count := 0
	err = jsonLines(out, func(b []byte) error {
		var row struct {
			Host        string   `json:"host"`
			Port        string   `json:"port"`
			Version     string   `json:"tls_version"`
			Cipher      string   `json:"cipher"`
			NotAfter    string   `json:"not_after"`
			Names       []string `json:"subject_an"`
			Issuer      string   `json:"issuer_cn"`
			SelfSigned  bool     `json:"self_signed"`
			Mismatched  bool     `json:"mismatched"`
			Untrusted   bool     `json:"untrusted"`
			ProbeStatus bool     `json:"probe_status"`
		}
		if err := json.Unmarshal(b, &row); err != nil {
			return err
		}
		if !inScope(row.Host, c.Target.Domain) || !row.ProbeStatus {
			return nil
		}
		port, _ := strconv.Atoi(row.Port)
		origin := "https://" + net.JoinHostPort(row.Host, row.Port)
		for i := range cp.Assets {
			a := &cp.Assets[i]
			if a.Host != row.Host {
				continue
			}
			a.TLS = row.NotAfter
			for j := range a.Services {
				svc := &a.Services[j]
				if svc.Port == port {
					svc.TLSVersion = row.Version
					svc.Cipher = row.Cipher
					svc.CertificateExpiry = row.NotAfter
					svc.CertificateNames = row.Names
					svc.Issuer = row.Issuer
					svc.SelfSigned = row.SelfSigned
					svc.Mismatched = row.Mismatched
					svc.Untrusted = row.Untrusted
				}
			}
			for _, issue := range []struct {
				match               bool
				id, title, severity string
			}{{row.SelfSigned, "tls-self-signed", "Self-signed TLS certificate", "medium"}, {row.Mismatched, "tls-name-mismatch", "TLS certificate hostname mismatch", "medium"}, {row.Untrusted, "tls-untrusted", "Untrusted TLS certificate chain", "medium"}} {
				if issue.match {
					cp.Findings = append(cp.Findings, Finding{Host: a.Host, Template: issue.id, MatchedAt: origin, Title: issue.title, Severity: issue.severity, Description: "TLSx observed a certificate trust or name mismatch on this public service.", Remediation: "Install a publicly trusted certificate covering the served hostname and provide the full certificate chain.", Evidence: fmt.Sprintf("TLSx host: %s\nTLS: %s\nCipher: %s\nIssuer: %s\nExpiry: %s", origin, row.Version, row.Cipher, row.Issuer, row.NotAfter)})
				}
			}
			if cp.SecretCoverage == nil {
				cp.SecretCoverage = map[string][]string{}
			}
			cp.SecretCoverage[a.Host] = append(cp.SecretCoverage[a.Host], "tls-self-signed", "tls-name-mismatch", "tls-untrusted")
			count++
			break
		}
		return nil
	})
	return cp, fmt.Sprintf("TLSx assessed %d public TLS services; protocol, cipher, SAN, issuer, expiry and trust metadata. %s", count, logs), err
}
func (w *Worker) historical(ctx context.Context, c Claim, cp Checkpoint, proxy, dir string) (Checkpoint, string, error) {
	runner := command
	if w.scannerCommand != nil {
		runner = w.scannerCommand
	}
	out, logs, err := runner(ctx, "gau", []string{c.Target.Domain, "--providers", "wayback,commoncrawl", "--subs", "--threads", "1", "--timeout", "12", "--retries", "0", "--proxy", proxy}, proxy, dir)
	if err != nil {
		cp.SourceIssues = append(cp.SourceIssues, "Historical providers unavailable; live scan continues.")
		return cp, "Historical discovery unavailable: " + logs, nil
	}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		u, ok := scopedEndpoint(strings.TrimSpace(scanner.Text()), c.Target.Domain)
		if !ok {
			continue
		}
		params := []string{}
		for k := range u.Query() {
			params = append(params, k)
		}
		sort.Strings(params)
		u.RawQuery = ""
		id := fingerprint(c.Target.ID, u.String())
		if seen[id] {
			continue
		}
		seen[id] = true
		if len(cp.History) >= 2000 {
			cp.SourceIssues = append(cp.SourceIssues, "Historical discovery capped at 2000 unique paths.")
			break
		}
		cp.History = append(cp.History, Endpoint{ID: id, URL: u.String(), Method: "Historical", Kind: endpointKind(u, ""), Source: "gau:wayback/commoncrawl", Parameters: params, TargetID: c.Target.ID, Historical: true})
	}
	return cp, fmt.Sprintf("GAU collected %d historical paths; not treated as live services or fetched from targets. %s", len(cp.History), logs), scanner.Err()
}
func serviceOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Host
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		host = u.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return u.Scheme + "://" + host
}

func resumeNetworkCheckpoint(old Checkpoint) Checkpoint {
	cp := Checkpoint{Hosts: old.Hosts, DNS: old.DNS, PortResults: old.PortResults, KnownSecrets: old.KnownSecrets}
	for _, a := range old.Assets {
		fresh := Asset{Host: a.Host, Type: "Domain", IP: a.IP, Source: a.Source, Ports: a.Ports, Technologies: []string{}}
		for _, ip := range old.DNS[a.Host] {
			address, err := netip.ParseAddr(ip)
			if err != nil || !publicIP(address) {
				fresh.Blocked = true
				cp.Blocked = append(cp.Blocked, a.Host)
				break
			}
		}
		cp.Assets = append(cp.Assets, fresh)
	}
	return cp
}
