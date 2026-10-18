package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoint inventory stores parameter names, never captured values or response bodies.
type Endpoint struct {
	TargetID     string   `json:"targetId,omitempty"`
	Historical   bool     `json:"historical,omitempty"`
	ID           string   `json:"id"`
	URL          string   `json:"url"`
	Method       string   `json:"method"`
	Status       int      `json:"status"`
	Kind         string   `json:"kind"`
	Source       string   `json:"source"`
	Parameters   []string `json:"parameters"`
	FirstSeen    string   `json:"firstSeen"`
	LastSeen     string   `json:"lastSeen"`
	MissingScans int      `json:"missingScans"`
	Removed      bool     `json:"removed"`
}

func scopedEndpoint(raw, root string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || !inScope(strings.ToLower(u.Hostname()), root) || (u.Port() != "" && !webPort(u.Port())) || len(raw) > 2048 {
		return nil, false
	}
	u.Fragment = ""
	return u, true
}
func endpointKind(u *url.URL, tag string) string {
	path := strings.ToLower(u.Path)
	if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") {
		return "JavaScript"
	}
	if tag == "form" {
		return "Form"
	}
	if strings.Contains(path, "swagger") || strings.Contains(path, "openapi") {
		return "API schema"
	}
	if strings.Contains(path, "/api/") || strings.Contains(path, "graphql") {
		return "API endpoint"
	}
	return "Page"
}

// A completed seed means the bounded crawl profile finished, not an exhaustive crawl.
func crawlSeeds(cp Checkpoint) []string {
	unique := map[string]bool{}
	for _, a := range cp.Assets {
		if a.Blocked || a.URL == "" {
			continue
		}
		urls := []string{a.URL}
		if len(a.Services) > 0 {
			urls = nil
			for _, svc := range a.Services {
				urls = append(urls, svc.URL)
			}
		}
		for _, raw := range urls {
			if origin := serviceOrigin(raw); origin != "" {
				unique[origin] = true
			}
		}
	}
	seeds := []string{}
	for seed := range unique {
		seeds = append(seeds, seed)
	}
	sort.Strings(seeds)
	return seeds
}
func crawlStageTimeout(cp Checkpoint, scans ...Scan) time.Duration {
	remaining := 0
	for _, seed := range crawlSeeds(cp) {
		if !cp.CrawlResults[seed] {
			remaining++
		}
	}
	workers := 1
	if len(scans) > 0 {
		workers = min(scanConcurrency(scans[0], 5), max(1, scans[0].Rate))
	}
	waves := (remaining + workers - 1) / workers
	return min(20*time.Minute, max(7*time.Minute, time.Duration(waves)*110*time.Second+10*time.Second))
}
func (w *Worker) crawl(ctx context.Context, c Claim, cp Checkpoint, proxy, dir string) (Checkpoint, string, error) {
	seeds := crawlSeeds(cp)
	if len(seeds) == 0 {
		return cp, "No available web services to crawl.", nil
	}
	if cp.CrawlResults == nil {
		cp.CrawlResults = map[string]bool{}
	}
	// Mark unfinished seeds before committing any progress, so interruption is resumable.
	refresh := func() {
		cp.CrawlIncomplete = nil
		for _, seed := range seeds {
			if !cp.CrawlResults[seed] {
				cp.CrawlIncomplete = append(cp.CrawlIncomplete, seed)
			}
		}
	}
	refresh()
	scope := `^https?://([a-zA-Z0-9-]+\.)*` + regexp.QuoteMeta(c.Target.Domain) + `(:80|:443|:3000|:8000|:8080|:8443|:8888|:9000|:9090|:9200|:9443)?(/|$)`
	runner := command
	if w.scannerCommand != nil {
		runner = w.scannerCommand
	}
	issues := []string{}
	concurrency := c.Scan.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > 5 {
		concurrency = 5
	}
	var pending []string
	for _, seed := range seeds {
		if !cp.CrawlResults[seed] {
			pending = append(pending, seed)
		}
	}
	if len(pending) > 0 {
		type seedResult struct {
			seed   string
			output []byte
			logs   string
			err    error
		}
		workers := min(len(pending), min(concurrency, max(1, c.Scan.Rate)))
		seedCh := make(chan string, len(pending))
		results := make(chan seedResult, workers)
		for _, seed := range pending {
			seedCh <- seed
		}
		close(seedCh)
		workCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for seed := range seedCh {
					if workCtx.Err() != nil {
						return
					}
					if deadline, ok := workCtx.Deadline(); ok && time.Until(deadline) < 110*time.Second {
						return
					}
					seedCtx, stop := context.WithTimeout(workCtx, 110*time.Second)
					output, logs, runErr := runner(seedCtx, "katana", []string{"-u", seed, "-jsonl", "-silent", "-duc", "-or", "-ob", "-d", "3", "-jc", "-fx", "-ct", "90s", "-mdp", "200", "-iqp", "-kf", "all", "-c", strconv.Itoa(max(1, concurrency/workers)), "-p", "1", "-rl", strconv.Itoa(min(2, max(1, c.Scan.Rate/workers))), "-timeout", "8", "-retry", "0", "-mrs", "262144", "-s", "breadth-first", "-dr", "-cs", scope, "-cos", `(?i)/(logout|log-out|delete|remove|unsubscribe)(/|\?|$)`, "-proxy", proxy, "-H", "X-Scanner: Surfacer/" + c.Scan.ID, "-H", "User-Agent: " + scannerAgent(c.Scan.ID, "crawl")}, proxy, dir)
					stop()
					// Always drain results, including observations made before cancellation.
					results <- seedResult{seed, completeScannerRecords(output, runErr), logs, runErr}
				}
			}()
		}
		go func() { wg.Wait(); close(results) }()
		var commitErr error
		for result := range results {
			var parseErr error
			cp, parseErr = parseCrawlOutput(cp, c.Target.Domain, result.output)
			if result.err == nil && parseErr == nil {
				cp.CrawlResults[result.seed] = true
			}
			refresh()
			if result.err != nil || parseErr != nil {
				cp.SourceIssues = append(cp.SourceIssues, fmt.Sprintf("Seed %s incomplete: %v", result.seed, errors.Join(result.err, parseErr)))
				issues = append(issues, fmt.Sprintf("%s incomplete: %v %v %s", result.seed, result.err, parseErr, capString(result.logs, 300)))
			}
			if commitErr == nil && ctx.Err() == nil {
				log := fmt.Sprintf("Katana: %d/%d service seeds finished; %d seeds incomplete.", len(seeds)-len(cp.CrawlIncomplete), len(seeds), len(cp.CrawlIncomplete))
				commitErr = w.checkpoint(ctx, c, "Endpoint crawling", cp, log)
				if commitErr != nil {
					cancel()
				}
			}
		}
		if ctx.Err() != nil && commitErr == nil {
			commitErr = w.checkpoint(ctx, c, "Endpoint crawling", cp, "Crawl stopped; observations retained.")
		}
		if commitErr != nil {
			return cp, "Crawl checkpoint failed; observations retained locally.", commitErr
		}
		if ctx.Err() != nil {
			return cp, "Crawl stopped; discoveries retained.", ctx.Err()
		}
	}
	refresh()
	count := 0
	for _, a := range cp.Assets {
		count += len(a.Endpoints)
	}
	log := fmt.Sprintf("%d scoped endpoints; %d/%d service seeds finished; depth 3; 90s/seed; query values omitted.", count, len(seeds)-len(cp.CrawlIncomplete), len(seeds))
	if len(cp.CrawlIncomplete) > 0 {
		log += " Crawl coverage incomplete; discoveries retained; Resume scan continues unfinished seeds."
	}
	if len(issues) > 0 {
		log += "\n" + strings.Join(issues, "\n")
	}
	return cp, log, nil
}
func parseCrawlOutput(cp Checkpoint, root string, output []byte) (Checkpoint, error) {
	seen := map[string]bool{}
	count := 0
	for _, a := range cp.Assets {
		for _, e := range a.Endpoints {
			seen[e.ID] = true
			count++
		}
	}
	err := jsonLines(output, func(line []byte) error {
		var row struct {
			Request  struct{ Endpoint, Method, Tag, Attribute, Source string }
			Response struct {
				StatusCode int `json:"status_code"`
				Forms      []struct {
					Method     string   `json:"method"`
					Action     string   `json:"action"`
					Parameters []string `json:"parameters"`
				} `json:"forms"`
			}
			Error string
		}
		if e := json.Unmarshal(line, &row); e != nil {
			return e
		}
		u, ok := scopedEndpoint(row.Request.Endpoint, root)
		if !ok {
			return nil
		}
		method := strings.ToUpper(row.Request.Method)
		if method == "" {
			method = "GET"
		}
		params := []string{}
		for key := range u.Query() {
			if len(params) < 100 {
				params = append(params, capString(key, 100))
			}
		}
		sort.Strings(params)
		u.RawQuery = ""
		canonical := u.String()
		key := fingerprint(method, canonical)
		if seen[key] {
			return nil
		}
		seen[key] = true
		if count >= 2000 {
			return fmt.Errorf("crawl endpoint cap reached; results are incomplete")
		}
		for i := range cp.Assets {
			a := &cp.Assets[i]
			if a.Host != u.Hostname() {
				continue
			}
			a.Endpoints = append(a.Endpoints, Endpoint{ID: key, URL: canonical, Method: method, Status: row.Response.StatusCode, Kind: endpointKind(u, row.Request.Tag), Source: "katana", Parameters: params})
			count++
			break
		}
		for _, form := range row.Response.Forms {
			action, err := u.Parse(form.Action)
			if err != nil {
				continue
			}
			target, ok := scopedEndpoint(action.String(), root)
			if !ok {
				continue
			}
			target.RawQuery = ""
			method := strings.ToUpper(form.Method)
			if method == "" {
				method = "GET"
			}
			key := fingerprint(method, target.String())
			if seen[key] {
				continue
			}
			seen[key] = true
			if count >= 2000 {
				return fmt.Errorf("crawl endpoint cap reached")
			}
			fields := []string{}
			for _, name := range form.Parameters {
				if len(fields) < 100 {
					fields = append(fields, capString(name, 100))
				}
			}
			for i := range cp.Assets {
				if cp.Assets[i].Host == target.Hostname() {
					cp.Assets[i].Endpoints = append(cp.Assets[i].Endpoints, Endpoint{ID: key, URL: target.String(), Method: method, Kind: "Form", Source: "katana:form", Parameters: fields})
					count++
					break
				}
			}
		}
		return nil
	})
	return cp, err
}
func (w *Worker) analyzeJavaScript(ctx context.Context, c Claim, cp Checkpoint, proxy, dir string) (Checkpoint, string, error) {
	jsDir := filepath.Join(dir, "javascript")
	if err := os.MkdirAll(jsDir, 0700); err != nil {
		return cp, "", err
	}
	p, err := url.Parse(proxy)
	if err != nil {
		return cp, "", err
	}
	transport := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ResponseHeaderTimeout: 10 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("stopped after 3 redirects")
			}
			if !inScope(req.URL.Hostname(), c.Target.Domain) {
				return errors.New("redirect escaped verified scope")
			}
			return nil
		},
	}
	sources := map[string]string{}
	hosts := map[string]bool{}
	failed := map[string]bool{}
	expected := map[string]int{}
	downloaded := map[string]int{}
	seenURLs := map[string]bool{}
	total := 0
	type jsTask struct {
		host string
		url  string
	}
	var tasks []jsTask
	for _, a := range cp.Assets {
		if a.Blocked {
			continue
		}
		for _, e := range a.Endpoints {
			if e.Kind != "JavaScript" {
				continue
			}
			if _, ok := scopedEndpoint(e.URL, c.Target.Domain); !ok {
				continue
			}
			if seenURLs[e.URL] {
				continue
			}
			seenURLs[e.URL] = true
			expected[a.Host]++
			if len(tasks) < 100 {
				tasks = append(tasks, jsTask{host: a.Host, url: e.URL})
			}
		}
	}

	interval := 500 * time.Millisecond
	if c.Scan.Rate > 0 {
		interval = time.Second / time.Duration(max(1, c.Scan.Rate))
	}
	limiter := time.NewTicker(interval)
	defer limiter.Stop()

	if len(tasks) > 0 {
		var mu sync.Mutex
		workers := min(len(tasks), scanConcurrency(c.Scan, 6))
		taskCh := make(chan jsTask, len(tasks))
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
					mu.Lock()
					stopTasks := len(sources) >= 100 || total >= 16<<20
					mu.Unlock()
					if stopTasks {
						continue
					}

					select {
					case <-ctx.Done():
						return
					case <-limiter.C:
					}

					req, err := http.NewRequestWithContext(ctx, "GET", t.url, nil)
					if err != nil {
						continue
					}
					req.Header.Set("X-Scanner", "Surfacer/"+c.Scan.ID)
					req.Header.Set("User-Agent", scannerAgent(c.Scan.ID, "secrets"))
					res, err := client.Do(req)
					if err != nil {
						continue
					}
					if res.StatusCode != 200 {
						res.Body.Close()
						if res.StatusCode == 403 || res.StatusCode == 429 || res.StatusCode == 503 {
							reportCooldown(ctx, proxy, t.host, res.StatusCode, res.Header.Get("Retry-After"))
						}
						continue
					}
					body, err := io.ReadAll(io.LimitReader(res.Body, (512<<10)+1))
					res.Body.Close()
					if err != nil || len(body) > 512<<10 {
						continue
					}
					name := fingerprint(t.url) + ".js"
					mu.Lock()
					if total+len(body) > 16<<20 || len(sources) >= 100 {
						mu.Unlock()
						continue
					}
					total += len(body)
					sources[name] = t.url
					mu.Unlock()
					writeErr := os.WriteFile(filepath.Join(jsDir, name), body, 0600)
					mu.Lock()
					if writeErr != nil {
						total -= len(body)
						delete(sources, name)
					} else {
						hosts[t.host] = true
						downloaded[t.host]++
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
	for h, count := range expected {
		if downloaded[h] < count {
			failed[h] = true
			delete(cp.SecretCoverage, h)
		}
	}
	if len(failed) > 0 {
		setStageIssue(&cp, "JavaScript secrets", fmt.Errorf("JavaScript downloads incomplete for %d hosts; unchecked secret history retained", len(failed)))
	}
	if len(sources) == 0 {
		for h := range failed {
			cp.Blocked = append(cp.Blocked, h)
		}
		return cp, "No public JavaScript files available for secret analysis.", javascriptCoverageError(failed)
	}
	report := filepath.Join(dir, "gitleaks.json")
	runner := command
	if w.scannerCommand != nil {
		runner = w.scannerCommand
	}
	_, logs, err := runner(ctx, "gitleaks", []string{"dir", jsDir, "--report-format", "json", "--report-path", report, "--redact=100", "--exit-code", "0", "--no-banner", "--no-color", "--log-level", "error", "--timeout", "60"}, "", dir)
	if err != nil {
		return cp, logs, err
	}
	if w.scannerCommand != nil {
		_ = os.WriteFile(report, []byte("[]"), 0600)
	}
	// Reports are ephemeral; only rule IDs and redacted evidence enter the checkpoint.
	data, err := os.ReadFile(report)
	if err != nil {
		return cp, "", err
	}
	if len(data) > 2<<20 {
		return cp, "", fmt.Errorf("secret report cap exceeded")
	}
	var rows []struct {
		RuleID, Description, File string
		StartLine                 int
	}
	if err = json.Unmarshal(data, &rows); err != nil {
		return cp, "", err
	}
	for _, r := range rows {
		source, ok := sources[filepath.Base(r.File)]
		if !ok {
			continue
		}
		u, _ := url.Parse(source)
		finding := Finding{
			Host:        u.Hostname(),
			Template:    "gitleaks:" + r.RuleID,
			MatchedAt:   source,
			Title:       "Public JavaScript secret: " + capString(r.Description, 200),
			Severity:    "high",
			Description: "Gitleaks matched a credential pattern in a publicly served JavaScript file. This is a potential secret; validity has not been tested.",
			Remediation: "Confirm whether the credential is sensitive. Remove it from client-side code, rotate or revoke it, and use server-side credential storage.",
			Evidence:    fmt.Sprintf("URL: %s\nRule: %s\nLine: %d\nSecret: [REDACTED]\nNo credential validation performed.", source, r.RuleID, r.StartLine),
			Category:    "secret",
			StageName:   "JavaScript secrets",
			Tool:        "gitleaks",
		}
		cp.Findings = append(cp.Findings, finding)
		Log(ctx).Info("finding_discovered", "stage", "JavaScript secrets", "host", finding.Host, "severity", finding.Severity, "template", finding.Template, "title", finding.Title, "matched_at", finding.MatchedAt)
	}
	if cp.SecretCoverage == nil {
		cp.SecretCoverage = map[string][]string{}
	}
	for h := range hosts {
		if failed[h] {
			continue
		}
		for _, f := range c.Scan.Checkpoint.KnownSecrets {
			if f.Host == h && sources[fingerprint(f.MatchedAt)+".js"] == f.MatchedAt {
				cp.SecretCoverage[h] = append(cp.SecretCoverage[h], f.Template)
			}
		}
		for _, f := range cp.Findings {
			if f.Host == h && strings.HasPrefix(f.Template, "gitleaks:") {
				cp.SecretCoverage[h] = append(cp.SecretCoverage[h], f.Template)
			}
		}
	}
	for h := range failed {
		if !hosts[h] {
			cp.Blocked = append(cp.Blocked, h)
		}
	}
	return cp, fmt.Sprintf("Gitleaks analyzed %d public JS files (%d bytes); %d redacted potential credentials; no credential testing. %s", len(sources), total, len(rows), logs), javascriptCoverageError(failed)
}

// Merge history only after actual successful crawl observations; partial runs retain old endpoints.
func mergeEndpoints(current, previous []Endpoint, stamp string, successful bool) []Endpoint {
	old := map[string]Endpoint{}
	for _, e := range previous {
		old[e.ID] = e
	}
	out := []Endpoint{}
	seen := map[string]bool{}
	for _, e := range current {
		e.FirstSeen = stamp
		e.LastSeen = stamp
		if p, ok := old[e.ID]; ok {
			e.FirstSeen = p.FirstSeen
		}
		e.MissingScans = 0
		e.Removed = false
		seen[e.ID] = true
		out = append(out, e)
	}
	for _, e := range previous {
		if seen[e.ID] {
			continue
		}
		if successful {
			e.MissingScans++
			if e.MissingScans >= 2 {
				e.Removed = true
			}
		}
		out = append(out, e)
	}
	return out
}

func endpointDelta(previous, current []Endpoint) (added, removed, returned int) {
	old := map[string]Endpoint{}
	for _, e := range previous {
		old[e.ID] = e
	}
	for _, e := range current {
		p, ok := old[e.ID]
		switch {
		case !ok:
			added++
		case !p.Removed && e.Removed:
			removed++
		case p.Removed && !e.Removed:
			returned++
		}
	}
	return
}

func javascriptCoverageError(failed map[string]bool) error {
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("JavaScript downloads incomplete for %d hosts; unchecked secret history retained", len(failed))
}
