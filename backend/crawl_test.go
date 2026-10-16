package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointHistoryRetainsPartialAndRemovesAfterTwoCleanScans(t *testing.T) {
	previous := []Endpoint{{ID: "one", URL: "https://company.com/api", FirstSeen: "first", LastSeen: "last"}}
	partial := mergeEndpoints(nil, previous, "today", false)
	if len(partial) != 1 || partial[0].MissingScans != 0 || partial[0].Removed {
		t.Fatal("partial crawl removed endpoint")
	}
	first := mergeEndpoints(nil, previous, "today", true)
	second := mergeEndpoints(nil, first, "tomorrow", true)
	if first[0].Removed || !second[0].Removed {
		t.Fatal("endpoint absence threshold not respected")
	}
	returned := mergeEndpoints([]Endpoint{{ID: "one", URL: "https://company.com/api"}}, second, "later", true)
	if returned[0].FirstSeen != "first" || returned[0].LastSeen != "later" || returned[0].Removed {
		t.Fatal("return lost endpoint history")
	}
}
func TestEndpointScopeRejectsCredentialsAndOtherOrigins(t *testing.T) {
	for _, raw := range []string{"https://company.com.evil.test/a", "http://127.0.0.1/a", "file:///etc/passwd", "https://user:password@company.com/a", "https://company.com:6666/a"} {
		if _, ok := scopedEndpoint(raw, "company.com"); ok {
			t.Errorf("unsafe endpoint allowed: %s", raw)
		}
	}
	for _, raw := range []string{"https://company.com/api", "http://api.company.com:80/a", "https://api.company.com:443/a"} {
		if _, ok := scopedEndpoint(raw, "company.com"); !ok {
			t.Errorf("scoped endpoint rejected: %s", raw)
		}
	}
}
func TestExpandedTemplateManifest(t *testing.T) {
	// Unknown protocol templates may never enter the curated set.
	w := Worker{Templates: "templates"}
	m, err := w.manifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Templates) < 14 {
		t.Fatal("expanded reviewed set is absent")
	}
	for _, entry := range m.Templates {
		if strings.Contains(entry.File, "default-login") {
			t.Fatal("credential guessing template included")
		}
	}
}

func TestCrawlDeadlineRetainsEndpointsAndResumesUnfinishedSeed(t *testing.T) {
	cp := Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example", Services: []Service{{URL: "https://owned.example:443", Port: 443}, {URL: "https://owned.example", Port: 443}}}, {Host: "b.owned.example", URL: "https://b.owned.example"}}}
	calls := 0
	w := Worker{scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		calls++
		if name != "katana" || args[0] != "-u" {
			t.Fatal("crawl still uses unbounded seed list")
		}
		if calls == 1 {
			return []byte(`{"request":{"endpoint":"https://b.owned.example/app.js?token=private","method":"GET"},"response":{"status_code":200,"forms":[{"method":"POST","action":"/submit","parameters":["email"]}]}}
{"request":`), "", fmt.Errorf("killed: %w", context.DeadlineExceeded)
		}
		return []byte(fmt.Sprintf("{\"request\":{\"endpoint\":\"%s/api\"},\"response\":{\"status_code\":200}}\n", args[1])), "", nil
	}}
	cp, log, err := w.crawl(context.Background(), Claim{Target: Target{Domain: "owned.example"}}, cp, "http://proxy", t.TempDir())
	if err != nil || calls != 2 || len(cp.CrawlResults) != 1 || len(cp.CrawlIncomplete) != 1 || !strings.Contains(log, "retained") {
		t.Fatalf("partial results lost: %v %s %#v", err, log, cp.CrawlResults)
	}
	endpoints := cp.Assets[1].Endpoints
	if len(endpoints) != 2 || endpoints[0].URL != "https://b.owned.example/app.js" || endpoints[0].Parameters[0] != "token" || endpoints[1].Method != "POST" {
		t.Fatalf("discoveries lost or secrets retained: %#v", endpoints)
	}
	cp, _, err = w.crawl(context.Background(), Claim{Target: Target{Domain: "owned.example"}}, cp, "http://proxy", t.TempDir())
	if err != nil || calls != 3 || len(cp.CrawlIncomplete) != 0 || len(cp.Assets[1].Endpoints) != 3 {
		t.Fatal("resume re-crawled completed seeds or erased endpoints", err, calls)
	}
	if err := validateCheckpoint(cp, "owned.example"); err != nil {
		t.Fatal("invalid crawl checkpoint", err)
	}
}
func TestCrawlBudgetRetainsExistingInventory(t *testing.T) {
	cp := Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example", Endpoints: []Endpoint{{ID: "old", URL: "https://owned.example/old"}}}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	w := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		t.Fatal("started seed without time to finish")
		return nil, "", nil
	}}
	cp, _, err := w.crawl(ctx, Claim{Target: Target{Domain: "owned.example"}}, cp, "", t.TempDir())
	if err != nil || len(cp.CrawlIncomplete) != 1 || len(cp.Assets[0].Endpoints) != 1 {
		t.Fatal("budget break lost resumable data")
	}
	for i := 0; i < 119; i++ {
		cp.Assets = append(cp.Assets, Asset{Host: fmt.Sprintf("h%d.owned.example", i), URL: fmt.Sprintf("https://h%d.owned.example", i)})
	}
	if crawlStageTimeout(cp) != 20*time.Minute {
		t.Fatal("large crawl still limited to seven minutes")
	}
}
func TestCrawlCheckpointProgressAndPartialLifecycle(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "fixture-worker")
	s := testServer(t)
	s.state = emptyState()
	s.allowUnverified = true
	s.liveEnabled = true
	sc := Scan{ID: "scan", TargetID: "target", Domain: "owned.example", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Stages: []Stage{{Name: "HTTP probing", Status: "completed"}, {Name: "Endpoint crawling", Status: "running", Attempts: 1}}}
	s.state.Scans = []Scan{sc}
	cp := Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example"}}, CrawlResults: map[string]bool{"https://owned.example": true}, CrawlIncomplete: []string{"https://b.owned.example"}}
	body, _ := json.Marshal(map[string]any{"worker": "fixture", "scanId": "scan", "lease": "lease", "stage": 1, "status": "progress", "checkpoint": cp})
	r := httptest.NewRequest("POST", "/internal/stage", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer fixture-worker")
	response := httptest.NewRecorder()
	s.handle(response, r)
	if response.Code != 200 || s.state.Scans[0].Stages[1].Attempts != 1 || !s.state.Scans[0].Checkpoint.CrawlResults["https://owned.example"] {
		t.Fatal("crawl progress not durable", response.Code, response.Body.String())
	}
	s.state.Assets = []Asset{{ID: fingerprint("target", "owned.example"), TargetID: "target", Host: "owned.example", Endpoints: []Endpoint{{ID: "prior", URL: "https://owned.example/old"}}}}
	sc.Checkpoint = cp
	sc.Stages[1].Status = "completed"
	s.normalize(&sc, true)
	s.normalize(&sc, true)
	if s.state.Assets[0].Endpoints[0].Removed || s.state.Assets[0].Endpoints[0].MissingScans != 0 {
		t.Fatal("incomplete crawl removed endpoint")
	}

	s.state.Scans[0].Stages[1].Status = "completed"
	r = httptest.NewRequest("POST", "/internal/complete", strings.NewReader(`{"worker":"fixture","scanId":"scan","lease":"lease"}`))
	r.Header.Set("Authorization", "Bearer fixture-worker")
	response = httptest.NewRecorder()
	s.handle(response, r)
	if response.Code != 200 || s.state.Scans[0].Status != "partial" || !strings.Contains(s.state.Scans[0].Error, "Crawling remains incomplete") {
		t.Fatal("unfinished crawl reported complete", response.Code, response.Body.String())
	}

	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	response = request(s, "POST", "/api/scans/scan/retry", `{}`)
	if response.Code != 200 || s.state.Scans[0].Stages[0].Status != "completed" || s.state.Scans[0].Stages[1].Status != "pending" || !s.state.Scans[0].Checkpoint.CrawlResults["https://owned.example"] {
		t.Fatal("retry lost crawl checkpoint", response.Code, response.Body.String())
	}
}
func TestCrawlCheckpointRejectsEscapedAndParameterizedSeeds(t *testing.T) {
	for _, seed := range []string{"https://evil.example", "https://owned.example/path", "https://owned.example?token=value", "https://user:password@owned.example", "https://owned.example:1234"} {
		if validateCheckpoint(Checkpoint{CrawlResults: map[string]bool{seed: true}}, "owned.example") == nil {
			t.Fatal("unsafe crawl seed accepted", seed)
		}
	}
}

func TestConcurrentCrawlSeeds(t *testing.T) {
	cp := Checkpoint{Assets: []Asset{
		{Host: "a.owned.example", URL: "https://a.owned.example"},
		{Host: "b.owned.example", URL: "https://b.owned.example"},
		{Host: "c.owned.example", URL: "https://c.owned.example"},
	}}
	w := Worker{scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		seed := args[1]
		return []byte(fmt.Sprintf("{\"request\":{\"endpoint\":\"%s/page\"},\"response\":{\"status_code\":200}}\n", seed)), "", nil
	}}
	result, _, err := w.crawl(context.Background(), Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Concurrency: 3}}, cp, "", t.TempDir())
	if err != nil {
		t.Fatalf("crawl failed: %v", err)
	}
	if len(result.CrawlResults) != 3 {
		t.Fatalf("expected 3 completed seeds, got %d", len(result.CrawlResults))
	}
	if len(result.CrawlIncomplete) != 0 {
		t.Fatalf("expected 0 incomplete seeds, got %d", len(result.CrawlIncomplete))
	}
}

func TestParallelJavaScriptDownload(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("console.log('secret=123');"))
	}))
	defer ts.Close()

	endpoints := make([]Endpoint, 10)
	for i := range endpoints {
		endpoints[i] = Endpoint{
			Kind: "JavaScript",
			URL:  fmt.Sprintf("http://owned.example/script%d.js", i),
		}
	}
	cp := Checkpoint{Assets: []Asset{
		{Host: "owned.example", URL: "http://owned.example", Endpoints: endpoints},
	}}
	w := Worker{scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		return []byte("[]"), "", nil
	}}
	claim := Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 20}}
	result, log, err := w.analyzeJavaScript(context.Background(), claim, cp, ts.URL, t.TempDir())
	if err != nil {
		t.Fatalf("analyzeJavaScript failed: %v", err)
	}
	if !strings.Contains(log, "Gitleaks analyzed 10 public JS files") {
		t.Fatalf("expected 10 public JS files analyzed, got log: %s", log)
	}
	if len(result.Blocked) != 0 {
		t.Fatalf("expected 0 blocked hosts, got: %v", result.Blocked)
	}
}

func TestCrawlEndpointErrorDoesNotBlockEntireHost(t *testing.T) {
	cp := Checkpoint{Assets: []Asset{
		{Host: "owned.example", URL: "https://owned.example"},
	}}
	output := []byte(`{"request":{"endpoint":"https://owned.example/valid1","method":"GET"},"response":{"status_code":200}}
{"request":{"endpoint":"https://owned.example/broken","method":"GET"},"response":{"status_code":0},"error":"dial timeout"}
{"request":{"endpoint":"https://owned.example/valid2","method":"GET"},"response":{"status_code":200}}
`)
	result, err := parseCrawlOutput(cp, "owned.example", output)
	if err != nil {
		t.Fatalf("parseCrawlOutput failed: %v", err)
	}
	if len(result.Blocked) != 0 {
		t.Fatalf("broken individual endpoint should not block entire host, got blocked: %v", result.Blocked)
	}
	if len(result.Assets[0].Endpoints) != 3 {
		t.Fatalf("expected 3 parsed endpoints, got %d", len(result.Assets[0].Endpoints))
	}
}

func TestJavaScriptSecretsRedirectOrPartialFailureDoesNotBlockHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect.js" {
			http.Redirect(w, r, "/target.js", http.StatusFound)
			return
		}
		if r.URL.Path == "/missing.js" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("console.log('clean');"))
	}))
	defer ts.Close()

	endpoints := []Endpoint{
		{Kind: "JavaScript", URL: "http://owned.example/script1.js"},
		{Kind: "JavaScript", URL: "http://owned.example/redirect.js"},
		{Kind: "JavaScript", URL: "http://owned.example/missing.js"},
	}
	cp := Checkpoint{Assets: []Asset{
		{Host: "owned.example", URL: "http://owned.example", Endpoints: endpoints},
	}}
	w := Worker{scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		return []byte("[]"), "", nil
	}}
	claim := Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 20}}
	result, _, err := w.analyzeJavaScript(context.Background(), claim, cp, ts.URL, t.TempDir())
	if err != nil {
		t.Fatalf("analyzeJavaScript failed: %v", err)
	}
	if len(result.Blocked) != 0 {
		t.Fatalf("host with at least one analyzed script should not be marked blocked, got: %v", result.Blocked)
	}
}

