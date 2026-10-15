package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var toolVersions = map[string]string{"subfinder": "2.17.0", "dnsx": "1.3.1", "httpx": "1.12.0", "nuclei": "3.11.1", "katana": "1.8.0", "gitleaks": "8.30.1", "naabu": "2.6.1", "tlsx": "1.4.0", "gau": "2.2.4"}

func scannerVersionArgs(name string) []string {
	if name == "gitleaks" || name == "gau" {
		return []string{"--version"}
	}
	return []string{"-version"}
}

type Worker struct {
	proxyLookup    func(context.Context, string) ([]net.IPAddr, error)
	scannerCommand func(context.Context, string, []string, string, string) ([]byte, string, error)
	ID             string
	API            string
	Token          string
	Templates      string
	client         *http.Client
}
type templateEntry struct {
	File         string `json:"file"`
	SHA256       string `json:"sha256"`
	Technology   string `json:"technology"`
	MetadataOnly bool   `json:"metadataOnly"`
	ID           string `json:"id"`
}
type templateManifest struct {
	Version   string          `json:"version"`
	Templates []templateEntry `json:"templates"`
}

func (w *Worker) call(ctx context.Context, path string, payload any, result any) error {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", w.API+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4000))
		return fmt.Errorf("API %d: %s", res.StatusCode, b)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(result)
	}
	return nil
}
func (w *Worker) payload(sc Scan) map[string]any {
	return map[string]any{"worker": w.ID, "versions": toolVersions, "scanId": sc.ID, "lease": sc.Lease}
}
func runWorker() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	id := os.Getenv("WORKER_ID")
	if id == "" {
		host, _ := os.Hostname()
		id = "worker-" + host
	}
	api := os.Getenv("WORKER_API_URL")
	if api == "" {
		api = "http://api:8080"
	}
	templates := os.Getenv("TEMPLATES_DIR")
	if templates == "" {
		templates = "/opt/surfacer/templates"
	}
	w := &Worker{ID: id, API: api, Token: os.Getenv("WORKER_TOKEN"), Templates: templates, client: &http.Client{Timeout: 15 * time.Second}}
	if w.Token == "" {
		log.Fatal("WORKER_TOKEN required")
	}
	if _, err := w.manifest(); err != nil {
		log.Fatal(err)
	}
	for name, version := range toolVersions {
		output, err := exec.Command(name, scannerVersionArgs(name)...).CombinedOutput()
		if err != nil || !strings.Contains(string(output), version) {
			log.Fatalf("Pinned %s %s unavailable: %s %v", name, version, output, err)
		}
	}
	log.Printf("Worker %s ready with pinned open-source scanners", id)
	for ctx.Err() == nil {
		var raw struct {
			Scan   *Scan  `json:"scan"`
			Target Target `json:"target"`
			Permit string `json:"permit"`
			Proxy  string `json:"proxy"`
			DNS    string `json:"dns"`
		}
		err := w.call(ctx, "/internal/claim", map[string]any{"worker": id, "versions": toolVersions}, &raw)
		if err != nil {
			log.Printf("claim: %v", err)
		}
		if err == nil && raw.Scan != nil {
			claim := Claim{*raw.Scan, raw.Target, raw.Permit, raw.Proxy, raw.DNS}
			w.execute(ctx, claim)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
func (w *Worker) manifest() (templateManifest, error) {
	var manifest templateManifest
	b, err := os.ReadFile(filepath.Join(w.Templates, "manifest.json"))
	if err != nil {
		return manifest, err
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		return manifest, err
	}
	if len(manifest.Templates) == 0 {
		return manifest, errors.New("no curated templates")
	}
	for i := range manifest.Templates {
		entry := &manifest.Templates[i]
		if filepath.Base(entry.File) != entry.File {
			return manifest, errors.New("invalid template path")
		}
		b, err = os.ReadFile(filepath.Join(w.Templates, entry.File))
		if err != nil {
			return manifest, err
		}
		hash := sha256.Sum256(b)
		if hex.EncodeToString(hash[:]) != entry.SHA256 || !bytes.Contains(b, []byte("# digest:")) {
			return manifest, fmt.Errorf("unsigned or modified template: %s", entry.File)
		}
		content := string(b)
		for _, line := range strings.Split(content, "\n") {
			if strings.HasPrefix(line, "id:") {
				entry.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			}
			if strings.HasPrefix(strings.TrimSpace(line), "tags:") {
				for _, tag := range strings.Split(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "tags:")), ",") {
					switch strings.TrimSpace(tag) {
					case "dos", "fuzz", "intrusive", "bruteforce":
						return manifest, errors.New("unsafe template tag")
					}
				}
			}
		}
		if entry.ID == "" || !strings.Contains(content, "\nhttp:") {
			return manifest, errors.New("only signed HTTP templates allowed")
		}
		for _, protocol := range []string{"\ncode:", "\nnetwork:", "\ndns:", "\nheadless:", "\nfile:", "\nflow:", "\njavascript:", "\nssl:", "\nwebsocket:"} {
			if strings.Contains(content, protocol) {
				return manifest, errors.New("non-HTTP template protocol or flow is prohibited")
			}
		}
	}
	return manifest, nil
}
func (w *Worker) execute(parent context.Context, claim Claim) {
	ctx, cancel := context.WithTimeout(parent, 60*time.Minute)
	defer cancel()
	sc := claim.Scan
	cp := sc.Checkpoint
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-finished:
				return
			case <-ticker.C:
				if err := w.call(ctx, "/internal/heartbeat", w.payload(sc), nil); err != nil {
					log.Printf("lease lost: %v", err)
					cancel()
					return
				}
			}
		}
	}()
	workdir, err := os.MkdirTemp("", "surfacer-scan-")
	if err != nil {
		return
	}
	defer os.RemoveAll(workdir)
	lookupProxy := net.DefaultResolver.LookupIPAddr
	if w.proxyLookup != nil {
		lookupProxy = w.proxyLookup
	}
	proxy, err := scannerProxy(ctx, claim.Proxy, lookupProxy)
	if err != nil {
		return
	}
	claim.Proxy = proxy.String()
	proxy.User = url.UserPassword("scan", claim.Permit)
	proxyURL := proxy.String()
	type historicalResult struct {
		history []Endpoint
		issues  []string
		logs    string
		err     error
	}
	var histCh chan historicalResult
	for stage := range sc.Stages {
		if sc.Stages[stage].Status == "completed" {
			continue
		}
		p := w.payload(sc)
		p["stage"] = stage
		p["status"] = "running"
		p["checkpoint"] = cp
		if err = w.call(ctx, "/internal/stage", p, nil); err != nil {
			return
		}
		stageBudget := 7 * time.Minute
		if sc.Stages[stage].Name == "Port discovery" {
			stageBudget = portStageTimeout(cp, sc.Rate)
		}
		if sc.Stages[stage].Name == "Endpoint crawling" {
			stageBudget = crawlStageTimeout(cp)
		}
		stageCtx, stop := context.WithTimeout(ctx, stageBudget)
		blockedBefore := len(cp.Blocked)
		logs := ""
		stageStart := time.Now()
		switch sc.Stages[stage].Name {
		case "Discovery":
			cp, logs, err = w.discover(stageCtx, claim, cp, proxyURL, workdir)
		case "DNS resolution":
			cp, logs, err = w.resolve(stageCtx, claim, cp, workdir)
			if err == nil && histCh == nil {
				histCh = make(chan historicalResult, 1)
				go func() {
					hCtx, hCancel := context.WithTimeout(ctx, 7*time.Minute)
					defer hCancel()
					hCp, hLogs, hErr := w.historical(hCtx, claim, Checkpoint{}, proxyURL, workdir)
					histCh <- historicalResult{history: hCp.History, issues: hCp.SourceIssues, logs: hLogs, err: hErr}
				}()
			}
		case "Port discovery":
			cp, logs, err = w.scanPorts(stageCtx, claim, cp, workdir)
		case "TLS assessment":
			cp, logs, err = w.assessTLS(stageCtx, claim, cp, workdir)
		case "Historical discovery":
			if histCh != nil {
				res := <-histCh
				cp.History = append(cp.History, res.history...)
				cp.SourceIssues = append(cp.SourceIssues, res.issues...)
				logs = res.logs
				err = res.err
			} else {
				cp, logs, err = w.historical(stageCtx, claim, cp, proxyURL, workdir)
			}
		case "HTTP probing":
			cp, logs, err = w.probe(stageCtx, claim, cp, proxyURL, workdir)
		case "TLS inspection":
			cp, logs, err = w.inspectCertificates(stageCtx, cp, proxyURL, sc.ID, sc.Rate)
		case "Endpoint crawling":
			cp, logs, err = w.crawl(stageCtx, claim, cp, proxyURL, workdir)
		case "JavaScript secrets":
			cp, logs, err = w.analyzeJavaScript(stageCtx, claim, cp, proxyURL, workdir)
		case "Detection":
			cp, logs, err = w.detect(stageCtx, claim, cp, proxyURL, workdir)
		case "Normalization":
			err = validateCheckpoint(cp, claim.Target.Domain)
			logs = "Results normalized with stable fingerprints and redacted evidence."
		case "Change detection":
			logs = "Lifecycle changes will be committed atomically with the completed scan."
		default:
			err = fmt.Errorf("unsupported scan stage: %s", sc.Stages[stage].Name)
		}
		stageDur := time.Since(stageStart)
		GlobalTelemetry.RecordStageDuration(sc.Stages[stage].Name, stageDur)
		if err != nil {
			Log(ctx).Error("worker_stage_failed", "scan_id", sc.ID, "stage", sc.Stages[stage].Name, "duration_ms", stageDur.Milliseconds(), "err", err.Error())
		} else {
			Log(ctx).Info("worker_stage_completed", "scan_id", sc.ID, "stage", sc.Stages[stage].Name, "duration_ms", stageDur.Milliseconds())
		}
		stop()
		if parent.Err() != nil {
			releaseCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			_ = w.call(releaseCtx, "/internal/release", w.payload(sc), nil)
			c()
			return
		}
		if ctx.Err() != nil {
			return
		}
		p = w.payload(sc)
		p["stage"] = stage
		p["checkpoint"] = cp
		if len(cp.Blocked) > blockedBefore {
			logs += fmt.Sprintf("\nIncomplete host coverage: %v", cp.Blocked[blockedBefore:])
		}
		p["log"] = logs
		p["status"] = "completed"
		if err != nil {
			p["status"] = "failed"
			p["error"] = err.Error()
		}
		if e := w.call(ctx, "/internal/stage", p, nil); e != nil {
			log.Printf("stage commit: %v", e)
			return
		}
		if err != nil {
			log.Printf("scan %s stage %d: %v", sc.ID, stage, err)
			return
		}
	}
	if err = w.call(ctx, "/internal/complete", w.payload(sc), nil); err != nil {
		log.Printf("complete: %v", err)
	}
}

type boundedBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - b.b.Len()
	if remaining < n {
		b.overflow = true
		p = p[:max(0, remaining)]
	}
	_, _ = b.b.Write(p)
	return n, nil
}
func command(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "XDG_CONFIG_HOME=" + dir + "/config", "HTTP_PROXY=" + proxy, "HTTPS_PROXY=" + proxy, "http_proxy=" + proxy, "https_proxy=" + proxy, "NO_PROXY=", "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
	stdout := &boundedBuffer{limit: 4 << 20}
	stderr := &boundedBuffer{limit: 32 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.overflow {
		err = errors.New("scanner output exceeded 4 MiB cap")
	}
	logText := redact(capString(stderr.b.String(), 4000))
	if err != nil {
		if ctx.Err() != nil {
			return stdout.b.Bytes(), logText, fmt.Errorf("%s stopped: %w (process: %v) · %s", name, ctx.Err(), err, logText)
		}
		return stdout.b.Bytes(), logText, fmt.Errorf("%s failed: %w · %s", name, err, logText)
	}
	return stdout.b.Bytes(), logText, nil
}
func jsonLines(data []byte, parse func([]byte) error) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if err := parse(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func writeList(dir, name string, values []string) (string, error) {
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(strings.Join(values, "\n")+"\n"), 0600)
	return path, err
}
func (w *Worker) discover(ctx context.Context, c Claim, cp Checkpoint, proxy, dir string) (Checkpoint, string, error) {
	output, logs, err := command(ctx, "subfinder", []string{"-d", c.Target.Domain, "-sources", "crtsh,hackertarget,rapiddns", "-oJ", "-cs", "-silent", "-duc", "-proxy", proxy, "-rl", "5", "-timeout", "20", "-max-time", "4"}, proxy, dir)
	if err != nil {
		return cp, logs, err
	}
	cp.Hosts = map[string][]string{c.Target.Domain: {"verified root"}}
	for _, h := range cp.Known {
		if inScope(h, c.Target.Domain) {
			cp.Hosts[h] = []string{"previous inventory"}
		}
	}
	err = jsonLines(output, func(b []byte) error {
		var result struct {
			Host    string   `json:"host"`
			Source  string   `json:"source"`
			Sources []string `json:"sources"`
		}
		if e := json.Unmarshal(b, &result); e != nil {
			return e
		}
		h := strings.ToLower(strings.TrimSuffix(result.Host, "."))
		if strings.HasPrefix(h, "*.") || !domainPattern.MatchString(h) || !inScope(h, c.Target.Domain) {
			return nil
		}
		if len(cp.Hosts) >= 1000 {
			return errors.New("discovery exceeds 1,000-host workspace limit")
		}
		sources := result.Sources
		if len(sources) == 0 {
			sources = []string{result.Source}
		}
		cp.Hosts[h] = sources
		return nil
	})
	return cp, fmt.Sprintf("%d in-scope names discovered. %s", len(cp.Hosts), logs), err
}
func (w *Worker) resolve(ctx context.Context, c Claim, cp Checkpoint, dir string) (Checkpoint, string, error) {
	hosts := []string{}
	for h := range cp.Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	input, err := writeList(dir, "hosts.txt", hosts)
	if err != nil {
		return cp, "", err
	}
	output, logs, err := command(ctx, "dnsx", []string{"-l", input, "-a", "-aaaa", "-j", "-silent", "-duc", "-r", c.DNS, "-rl", strconv.Itoa(c.Scan.Rate), "-t", strconv.Itoa(c.Scan.Concurrency), "-retry", "2", "-timeout", "5"}, "", dir)
	if err != nil {
		return cp, logs, err
	}
	cp.DNS = map[string][]string{}
	err = jsonLines(output, func(b []byte) error {
		var result struct {
			Host string   `json:"host"`
			A    []string `json:"a"`
			AAAA []string `json:"aaaa"`
		}
		if e := json.Unmarshal(b, &result); e != nil {
			return e
		}
		if inScope(result.Host, c.Target.Domain) {
			cp.DNS[result.Host] = append(result.A, result.AAAA...)
		}
		return nil
	})
	cp.Assets = []Asset{}
	cp.Blocked = []string{}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", c.DNS)
	}}
	var unresolved []string
	for _, h := range hosts {
		if len(cp.DNS[h]) == 0 {
			unresolved = append(unresolved, h)
		}
	}
	if len(unresolved) > 0 {
		var mu sync.Mutex
		workers := min(len(unresolved), 20)
		ch := make(chan string, len(unresolved))
		for _, h := range unresolved {
			ch <- h
		}
		close(ch)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for h := range ch {
					if ctx.Err() != nil {
						return
					}
					ips, e := resolver.LookupNetIP(ctx, "ip", h)
					mu.Lock()
					if e != nil {
						var dnsError *net.DNSError
						if errors.As(e, &dnsError) && dnsError.IsNotFound {
							cp.DNS[h] = []string{}
						} else {
							delete(cp.DNS, h)
							cp.Blocked = append(cp.Blocked, h)
						}
					} else {
						cp.DNS[h] = []string{}
						for _, ip := range ips {
							cp.DNS[h] = append(cp.DNS[h], ip.String())
						}
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}
	for _, h := range hosts {
		ips := cp.DNS[h]
		if len(ips) == 0 {
			continue
		}
		a := Asset{Host: h, IP: ips[0], Type: "Domain", Technologies: []string{}, Ports: []int{}, Severity: "none", Source: strings.Join(cp.Hosts[h], ", "), Title: h}
		for _, ip := range ips {
			addr, e := netip.ParseAddr(ip)
			if e != nil || !publicIP(addr) {
				a.Blocked = true
				cp.Blocked = append(cp.Blocked, h)
				break
			}
		}
		cp.Assets = append(cp.Assets, a)
	}
	return cp, fmt.Sprintf("%d resolved names; %d blocked non-public destinations. %s", len(cp.Assets), len(cp.Blocked), logs), err
}
func (w *Worker) probe(ctx context.Context, c Claim, cp Checkpoint, proxy, dir string) (Checkpoint, string, error) {
	hosts := []string{}
	for _, a := range cp.Assets {
		if !a.Blocked {
			if len(a.Ports) > 0 {
				for _, port := range a.Ports {
					if webPort(strconv.Itoa(port)) {
						scheme := "http"
						if port == 443 || port == 8443 || port == 9443 {
							scheme = "https"
						}
						hosts = append(hosts, scheme+"://"+net.JoinHostPort(a.Host, strconv.Itoa(port)))
					}
				}
			} else {
				hosts = append(hosts, a.Host)
			}
		}
	}
	if len(hosts) == 0 {
		return cp, "No public hosts to probe.", nil
	}
	input, err := writeList(dir, "public-hosts.txt", hosts)
	if err != nil {
		return cp, "", err
	}
	runner := command
	if w.scannerCommand != nil {
		runner = w.scannerCommand
	}
	output, logs, err := runner(ctx, "httpx", []string{"-l", input, "-json", "-silent", "-duc", "-status-code", "-probe", "-no-fallback-scheme", "-title", "-tech-detect", "-ip", "-tls-grab", "-proxy", proxy, "-H", "X-Scanner: Surfacer/" + c.Scan.ID, "-H", "User-Agent: " + scannerAgent(c.Scan.ID, "http"), "-random-agent=false", "-rl", strconv.Itoa(c.Scan.Rate), "-threads", strconv.Itoa(c.Scan.Concurrency), "-timeout", "10", "-retries", "1", "-r", c.DNS, "-follow-host-redirects", "-max-redirects", "3", "-response-size-to-read", "65536"}, proxy, dir)
	incomplete := errors.Is(err, context.DeadlineExceeded)
	if err != nil && !incomplete {
		return cp, logs, err
	}
	if incomplete {
		if last := bytes.LastIndexByte(output, '\n'); last >= 0 {
			output = output[:last+1]
		}
	}
	responses := map[string]bool{}
	failedHosts := map[string][]string{}
	err = jsonLines(output, func(b []byte) error {
		var result struct {
			URL    string   `json:"url"`
			Failed bool     `json:"failed"`
			Error  string   `json:"error"`
			Status int      `json:"status_code"`
			Title  string   `json:"title"`
			Tech   []string `json:"tech"`
			Host   string   `json:"host"`
			TLS    struct {
				NotAfter string `json:"not_after"`
			} `json:"tls"`
		}
		if e := json.Unmarshal(b, &result); e != nil {
			return e
		}
		u, e := url.Parse(result.URL)
		if e != nil || !inScope(u.Hostname(), c.Target.Domain) {
			return nil
		}
		responses[serviceOrigin(result.URL)] = true
		if result.Failed || result.Status < 100 || result.Status > 599 {
			failedHosts[u.Hostname()] = append(failedHosts[u.Hostname()], capString(redact(result.Error), 300))
			return nil
		}
		for i := range cp.Assets {
			a := &cp.Assets[i]
			if a.Host != u.Hostname() {
				continue
			}
			a.Type = "Web service"
			if a.URL == "" || (a.Status >= 400 && result.Status < 400) {
				a.URL = result.URL
				a.Status = result.Status
				a.Title = capString(result.Title, 300)
			}
			for _, tech := range result.Tech {
				if !contains(a.Technologies, tech) {
					a.Technologies = append(a.Technologies, tech)
				}
			}
			if a.Technologies == nil {
				a.Technologies = []string{}
			}
			port := 80
			if u.Scheme == "https" {
				port = 443
			}
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			}
			if !contains(intStrings(a.Ports), strconv.Itoa(port)) {
				a.Ports = append(a.Ports, port)
			}
			a.Services = append(a.Services, Service{URL: result.URL, Port: port, Status: result.Status, Title: capString(result.Title, 300), Technologies: result.Tech})
			if result.TLS.NotAfter != "" {
				a.TLS = result.TLS.NotAfter
			}
			if result.Status >= 500 || result.Status == 429 || result.Status == 403 {
				cp.Blocked = append(cp.Blocked, a.Host)
				if result.Status == 403 || result.Status == 429 || result.Status == 503 {
					reportCooldown(ctx, proxy, a.Host, result.Status, "")
				}
			}
			break
		}
		return nil
	})
	if incomplete {
		missing := 0
		for _, target := range hosts {
			if !strings.Contains(target, "://") {
				target = "https://" + target
			}
			u, e := url.Parse(target)
			if e != nil || u.Hostname() == "" {
				continue
			}
			if !responses[serviceOrigin(target)] {
				missing++
				cp.Blocked = append(cp.Blocked, u.Hostname())
			}
		}
		issue := fmt.Sprintf("HTTP stage budget reached: retained %d completed probe records; %d requested services have no completed response. Unchecked findings are retained.", len(responses), missing)
		logs += "\n" + issue
		cp.SourceIssues = append(cp.SourceIssues, issue)
	}
	live := 0
	for _, a := range cp.Assets {
		if a.URL == "" && len(failedHosts[a.Host]) > 0 {
			cp.Blocked = append(cp.Blocked, a.Host)
			cp.SourceIssues = append(cp.SourceIssues, "HTTP probing failed for "+a.Host+": "+failedHosts[a.Host][0])
		}
		if a.URL != "" {
			live++
		}
	}
	examples := []string{}
	failed := 0
	for _, a := range cp.Assets {
		if a.URL == "" && len(failedHosts[a.Host]) > 0 {
			failed++
			if len(examples) < 3 {
				examples = append(examples, a.Host+": "+failedHosts[a.Host][0])
			}
		}
	}
	if failed > 0 {
		logs += fmt.Sprintf("\n%d hosts had no successful HTTP probe. %s", failed, strings.Join(examples, "; "))
	}
	return cp, fmt.Sprintf("%d live web hosts identified. %s", live, logs), err
}
func (w *Worker) inspectCertificates(ctx context.Context, cp Checkpoint, proxy, scanID string, rate int) (Checkpoint, string, error) {
	p, err := url.Parse(proxy)
	if err != nil {
		return cp, "", err
	}
	transport := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	limiter := time.NewTicker(time.Second / time.Duration(max(1, rate)))
	defer limiter.Stop()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	type inspectTask struct {
		index int
		host  string
		url   string
	}
	var tasks []inspectTask
	for i := range cp.Assets {
		a := &cp.Assets[i]
		if !a.Blocked && a.URL != "" {
			tasks = append(tasks, inspectTask{index: i, host: a.Host, url: a.URL})
		}
	}
	if len(tasks) > 0 {
		var mu sync.Mutex
		workers := max(2, min(len(tasks), min(rate, 8)))
		taskCh := make(chan inspectTask, len(tasks))
		for _, t := range tasks {
			taskCh <- t
		}
		close(taskCh)

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for t := range taskCh {
					select {
					case <-ctx.Done():
						return
					case <-limiter.C:
					}
					req, err := http.NewRequestWithContext(ctx, "HEAD", t.url, nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", scannerAgent(scanID, "tls"))
					req.Header.Set("X-Scanner", "Surfacer/"+scanID)
					response, err := client.Do(req)
					mu.Lock()
					if err != nil {
						cp.Blocked = append(cp.Blocked, t.host)
						mu.Unlock()
						continue
					}
					response.Body.Close()
					if response.StatusCode == 403 || response.StatusCode == 429 || response.StatusCode == 503 {
						cp.Assets[t.index].Blocked = true
						cp.Blocked = append(cp.Blocked, t.host)
						reportCooldown(ctx, proxy, t.host, response.StatusCode, response.Header.Get("Retry-After"))
					} else if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
						cp.Assets[t.index].TLS = response.TLS.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return cp, "", ctx.Err()
		}
	}
	return tlsFindings(cp)
}
func clarifyCertificateFinding(f *Finding) {
	if f.Template != "tls-expiry" {
		return
	}
	for _, line := range strings.Split(f.Evidence, "\n") {
		if !strings.HasPrefix(line, "Certificate expires: ") {
			continue
		}
		expires, err := time.Parse(time.RFC3339, strings.TrimPrefix(line, "Certificate expires: "))
		if err != nil {
			return
		}
		if time.Now().After(expires) {
			f.Title = "TLS certificate expired"
			f.Description = "The observed TLS certificate expired on " + expires.UTC().Format("2 Jan 2006") + ". Review the affected service and renew its certificate."
		} else {
			f.Title = "TLS certificate expiring soon"
			f.Description = "The observed TLS certificate expires on " + expires.UTC().Format("2 Jan 2006") + "."
		}
		return
	}
}

func tlsFindings(cp Checkpoint) (Checkpoint, string, error) {
	for _, a := range cp.Assets {
		if a.TLS == "" || a.Blocked {
			continue
		}
		expires, err := time.Parse(time.RFC3339, a.TLS)
		if err != nil {
			continue
		}
		if time.Until(expires) < 14*24*time.Hour {
			finding := Finding{Host: a.Host, Template: "tls-expiry", MatchedAt: a.URL, Title: "TLS certificate expiring soon", Severity: "medium", Description: "The observed TLS certificate expires within 14 days.", Remediation: "Renew the certificate and verify automatic renewal.", Evidence: "URL: " + a.URL + "\nCertificate expires: " + a.TLS}
			clarifyCertificateFinding(&finding)
			cp.Findings = append(cp.Findings, finding)
		}
	}
	return cp, "TLS certificate data extracted by HTTPx and evaluated with Go crypto/time libraries.", nil
}
func (w *Worker) detect(ctx context.Context, c Claim, cp Checkpoint, proxy, dir string) (Checkpoint, string, error) {
	manifest, err := w.manifest()
	if err != nil {
		return cp, "", err
	}
	cp.Covered = []string{}
	if c.Scan.TemplateSet == "v10.5.0-curated-1" {
		legacy := map[string]bool{"git-config.yaml": true, "laravel-env.yaml": true, "apache-server-status.yaml": true, "nginx-status.yaml": true}
		kept := []templateEntry{}
		for _, t := range manifest.Templates {
			if legacy[t.File] {
				kept = append(kept, t)
			}
		}
		manifest.Templates = kept
	}
	cp.ServiceCoverage = map[string][]string{}
	cp.Coverage = map[string][]string{}
	for h, rules := range cp.SecretCoverage {
		cp.Coverage[h] = append(cp.Coverage[h], rules...)
	}
	kept := []Finding{}
	for _, f := range cp.Findings {
		if strings.HasPrefix(f.Template, "tls-") || strings.HasPrefix(f.Template, "gitleaks:") {
			kept = append(kept, f)
		}
	}
	cp.Findings = kept
	for _, a := range cp.Assets {
		if a.TLS != "" && !a.Blocked {
			cp.Coverage[a.Host] = append(cp.Coverage[a.Host], "tls-expiry")
		}
	}
	cp.Templates = []string{}
	groups := map[string][]string{}
	paths := map[string][]string{}
	for _, a := range cp.Assets {
		if a.URL == "" || a.Blocked {
			continue
		}
		files := []string{}
		ids := []string{}
		for _, t := range manifest.Templates {
			match := t.Technology == ""
			for _, tech := range a.Technologies {
				if strings.EqualFold(tech, t.Technology) {
					match = true
				}
			}
			if match {
				files = append(files, filepath.Join(w.Templates, t.File))
				ids = append(ids, t.ID)
				cp.Templates = append(cp.Templates, t.ID)
			}
		}
		key := strings.Join(files, ",")
		if key == "" {
			continue
		}
		services := a.Services
		if len(services) == 0 {
			services = []Service{{URL: a.URL, Status: a.Status}}
		}
		for _, svc := range services {
			if svc.Status == 403 || svc.Status == 429 || svc.Status >= 500 {
				continue
			}
			groups[key] = append(groups[key], svc.URL)
		}
		paths[key] = ids
	}
	logs := []string{}
	for templates, urls := range groups {
		input, e := writeList(dir, "urls-"+fingerprint(templates)+".txt", urls)
		if e != nil {
			return cp, "", e
		}
		output, logText, e := command(ctx, "nuclei", []string{"-l", input, "-t", templates, "-jsonl", "-silent", "-duc", "-disable-unsigned-templates", "-etags", "dos,intrusive,fuzz,bruteforce", "-no-interactsh", "-proxy", proxy, "-H", "X-Scanner: Surfacer/" + c.Scan.ID, "-H", "User-Agent: " + scannerAgent(c.Scan.ID, "detection"), "-rl", strconv.Itoa(c.Scan.Rate), "-c", "1", "-pc", "1", "-bs", strconv.Itoa(c.Scan.Concurrency), "-timeout", "10", "-retries", "1", "-response-size-read", "65536", "-include-rr", "-matcher-status"}, proxy, dir)
		logs = append(logs, logText)
		parseErr := jsonLines(output, func(b []byte) error {
			var r struct {
				Template      string `json:"template-id"`
				Host          string `json:"host"`
				Matched       string `json:"matched-at"`
				URL           string `json:"url"`
				Request       string `json:"request"`
				Response      string `json:"response"`
				MatcherStatus *bool  `json:"matcher-status"`
				Error         string `json:"error"`
				Info          struct {
					Name        string `json:"name"`
					Severity    string `json:"severity"`
					Description string `json:"description"`
					Remediation string `json:"remediation"`
				} `json:"info"`
			}
			if err := json.Unmarshal(b, &r); err != nil {
				return err
			}
			value := r.Matched
			if value == "" {
				value = r.URL
				if value == "" {
					value = r.Host
				}
				if !strings.Contains(value, "://") {
					value = "http://" + value
				}
			}
			u, err := url.Parse(value)
			if err != nil || !inScope(u.Hostname(), c.Target.Domain) {
				return nil
			}
			if r.Error != "" || r.Response == "" || strings.Contains(r.Response, " 429 ") || strings.Contains(r.Response, " 503 ") {
				cp.Blocked = append(cp.Blocked, u.Hostname())
				return nil
			}
			cp.ServiceCoverage[serviceOrigin(value)] = append(cp.ServiceCoverage[serviceOrigin(value)], r.Template)
			cp.Coverage[u.Hostname()] = append(cp.Coverage[u.Hostname()], r.Template)
			if r.MatcherStatus == nil || !*r.MatcherStatus {
				return nil
			}
			if len(cp.Findings) >= 2000 {
				return errors.New("finding cap exceeded")
			}
			evidence := redact(capString(r.Request+"\n\n"+r.Response, 16<<10))
			for _, entry := range manifest.Templates {
				if entry.ID == r.Template && entry.MetadataOnly {
					evidence = fmt.Sprintf("Nuclei matched %s at %s. Sensitive response body omitted from stored evidence.", r.Template, value)
				}
			}
			cp.Findings = append(cp.Findings, Finding{Template: r.Template, Host: u.Hostname(), MatchedAt: r.Matched, Title: capString(r.Info.Name, 300), Severity: r.Info.Severity, Description: capString(r.Info.Description, 2000), Remediation: capString(r.Info.Remediation, 2000), Evidence: evidence})
			return nil
		})
		if e != nil {
			return cp, strings.Join(logs, "\n"), e
		}
		if parseErr != nil {
			return cp, strings.Join(logs, "\n"), parseErr
		}
		for _, value := range urls {
			u, _ := url.Parse(value)
			complete := true
			for _, template := range paths[templates] {
				if !contains(cp.ServiceCoverage[serviceOrigin(value)], template) {
					complete = false
				}
			}
			if complete {
				cp.Covered = append(cp.Covered, u.Hostname())
			} else {
				cp.Blocked = append(cp.Blocked, u.Hostname())
			}
		}
	}
	return cp, fmt.Sprintf("%d signed curated HTTP templates; %d findings; %d hosts covered. %s", len(manifest.Templates), len(cp.Findings), len(cp.Covered), strings.Join(logs, "\n")), nil
}

// Scanner DNS is pinned to public resolution. Resolve the trusted Docker proxy
// using system DNS first so tools do not send "gateway" to the public resolver.
func scannerProxy(ctx context.Context, raw string, lookup func(context.Context, string) ([]net.IPAddr, error)) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid scanner gateway URL")
	}
	if net.ParseIP(u.Hostname()) != nil {
		return u, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := lookup(lookupCtx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("scanner gateway DNS resolution failed")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	selected := ips[0].IP
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			selected = ip.IP
			break
		}
	}
	u.Host = net.JoinHostPort(selected.String(), port)
	return u, nil
}
