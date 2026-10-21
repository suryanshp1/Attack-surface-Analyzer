package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestInterruptedWorkerCheckpointsBeforeReleasingLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var statuses []string
	var saved Checkpoint
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Status     string     `json:"status"`
			Checkpoint Checkpoint `json:"checkpoint"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if r.URL.Path == "/internal/stage" {
			statuses = append(statuses, payload.Status)
			saved = payload.Checkpoint
		}
		if r.URL.Path == "/internal/release" {
			statuses = append(statuses, "released")
		}
		w.WriteHeader(200)
	}))
	defer api.Close()
	worker := Worker{API: api.URL, client: api.Client(), proxyLookup: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}, scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		cancel()
		return []byte("{\"host\":\"app.owned.example\",\"source\":\"fixture\"}\n"), "", context.Canceled
	}}
	worker.execute(ctx, Claim{Proxy: "http://gateway:3128", Target: Target{Domain: "owned.example"}, Scan: Scan{Stages: []Stage{{Name: "Discovery"}}}})
	if strings.Join(statuses, ",") != "running,progress,released" || saved.Hosts["app.owned.example"] == nil || saved.IncompleteStages["Discovery"] == "" {
		t.Fatal("worker released before durable observations", statuses, saved)
	}
}

func TestKnownSecretCoverageRequiresTheOriginalFile(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "clean") }))
	defer proxy.Close()
	w := Worker{scannerCommand: func(_ context.Context, name string, args []string, _, _ string) ([]byte, string, error) {
		if name == "retire" {
			return cleanRetireOutput(args), "", nil
		}
		return nil, "", nil
	}}
	known := []Finding{{Host: "owned.example", Template: "gitleaks:checked", MatchedAt: "http://owned.example/app.js"}, {Host: "owned.example", Template: "gitleaks:unchecked", MatchedAt: "http://owned.example/old.js"}}
	claim := Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 30, Concurrency: 1, Checkpoint: Checkpoint{KnownSecrets: known}}}
	cp, _, err := w.analyzeJavaScript(context.Background(), claim, Checkpoint{Assets: []Asset{{Host: "owned.example", Endpoints: []Endpoint{{Kind: "JavaScript", URL: "http://owned.example/app.js"}}}}}, proxy.URL, t.TempDir())
	if err != nil || !contains(cp.SecretCoverage["owned.example"], "gitleaks:checked") || contains(cp.SecretCoverage["owned.example"], "gitleaks:unchecked") {
		t.Fatal("secret coverage transferred between files", err, cp.SecretCoverage)
	}
}

func TestScanCompletionEmitsObservationsWithoutReenteringWorkspaceLock(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "fixture-worker")
	s := testServer(t)
	s.state = emptyState()
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example"}}
	s.state.Scans = []Scan{{ID: "scan", TargetID: "target", Domain: "owned.example", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Stages: []Stage{{Name: "Normalization", Status: "completed"}}, Checkpoint: Checkpoint{Assets: []Asset{{Host: "owned.example", IP: "1.1.1.1", URL: "https://owned.example"}}}}}
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("POST", "/internal/complete", strings.NewReader(`{"worker":"fixture","scanId":"scan","lease":"lease"}`))
		r.Header.Set("Authorization", "Bearer fixture-worker")
		response := httptest.NewRecorder()
		s.handle(response, r)
		done <- response.Code
	}()
	select {
	case status := <-done:
		if status != 200 || len(s.state.Assets) != 1 || len(s.state.Events) == 0 {
			t.Fatal("scan observations not committed", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("normalization deadlocked during event emission")
	}
}

func TestJavaScriptBudgetsDoNotCreditPartialFileCoverage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		files, size int
	}{{"file cap", 101, 16}, {"byte cap", 34, 512 << 10}} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("x", tc.size)
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer proxy.Close()
			cp := Checkpoint{Assets: []Asset{{Host: "owned.example"}}}
			for i := 0; i < tc.files; i++ {
				cp.Assets[0].Endpoints = append(cp.Assets[0].Endpoints, Endpoint{Kind: "JavaScript", URL: fmt.Sprintf("http://owned.example/%d.js", i)})
			}
			worker := Worker{scannerCommand: func(_ context.Context, name string, args []string, _, _ string) ([]byte, string, error) {
				if name == "retire" {
					return cleanRetireOutput(args), "", nil
				}
				files, e := os.ReadDir(args[1])
				if e != nil {
					return nil, "", e
				}
				var bytes int64
				for _, file := range files {
					info, e := file.Info()
					if e != nil {
						return nil, "", e
					}
					bytes += info.Size()
				}
				if bytes > 16<<20 || len(files) > 100 {
					return nil, "", errors.New("JavaScript disk budget exceeded")
				}
				return nil, "", nil
			}}
			claim := Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 30, Concurrency: 6, Checkpoint: Checkpoint{KnownSecrets: []Finding{{Host: "owned.example", Template: "gitleaks:fixture", MatchedAt: "http://owned.example/0.js"}}}}}
			cp, _, err := worker.analyzeJavaScript(context.Background(), claim, cp, proxy.URL, t.TempDir())
			if err == nil || strings.Contains(err.Error(), "disk budget exceeded") || len(cp.SecretCoverage["owned.example"]) > 0 {
				t.Fatal("budgets exceeded or partial files credited as clean", err, cp.SecretCoverage)
			}
		})
	}
}

func TestStageEvidenceUploadDoesNotBlockHeartbeatAndFencesCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(strconv.FormatBool(canceled), func(t *testing.T) {
			t.Setenv("WORKER_TOKEN", "fixture-worker")
			uploading, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer func() { once.Do(func() { close(release) }) }()
			store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(uploading)
				<-release
				w.Header().Set("ETag", `"fixture"`)
				w.WriteHeader(200)
			}))
			defer store.Close()
			client, err := minio.New(strings.TrimPrefix(store.URL, "http://"), &minio.Options{Region: "us-east-1", Creds: credentials.NewStaticV4("fixture", "fixture", "")})
			if err != nil {
				t.Fatal(err)
			}
			s := testServer(t)
			s.state = emptyState()
			s.allowUnverified = true
			s.evidence = &EvidenceStore{client: client, bucket: "fixture-bucket"}
			s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
			s.state.Scans = []Scan{{ID: "scan", TargetID: "target", Domain: "owned.example", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Stages: []Stage{{Name: "Detection", Status: "running"}}}}
			call := func(path, body string) int {
				r := httptest.NewRequest("POST", path, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer fixture-worker")
				response := httptest.NewRecorder()
				s.handle(response, r)
				return response.Code
			}
			stageDone := make(chan int, 1)
			go func() {
				stageDone <- call("/internal/stage", `{"worker":"fixture","scanId":"scan","lease":"lease","stage":0,"status":"completed","checkpoint":{}}`)
			}()
			select {
			case <-uploading:
			case <-time.After(3 * time.Second):
				t.Fatal("upload did not start")
			}
			heartbeat := make(chan int, 1)
			go func() {
				heartbeat <- call("/internal/heartbeat", `{"worker":"fixture","scanId":"scan","lease":"lease"}`)
			}()
			select {
			case status := <-heartbeat:
				if status != 200 {
					t.Fatal("heartbeat failed", status)
				}
			case <-time.After(time.Second):
				once.Do(func() { close(release) })
				t.Fatal("evidence upload held API lock")
			}
			s.mu.Lock()
			if canceled {
				s.state.Scans[0].Status = "canceled"
				s.state.Scans[0].Lease = ""
			}
			// Force relocation of the slice while the stage handler is outside the lock.
			s.state.Scans = append([]Scan{{ID: "another-scan"}}, s.state.Scans...)
			s.mu.Unlock()
			once.Do(func() { close(release) })
			status := <-stageDone
			s.mu.Lock()
			defer s.mu.Unlock()
			if canceled && (status != 409 || s.state.Scans[1].Stages[0].Status != "running") {
				t.Fatal("canceled upload committed stale state", status)
			}
			if !canceled && (status != 200 || s.state.Scans[1].Stages[0].Status != "completed") {
				t.Fatal("stage lost after concurrent heartbeat", status)
			}
		})
	}
}

func TestExpiredLeaseCannotBeRenewedByLateHeartbeat(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "fixture-worker")
	s := testServer(t)
	s.state = emptyState()
	s.state.Scans = []Scan{{ID: "scan", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}}
	r := httptest.NewRequest("POST", "/internal/heartbeat", strings.NewReader(`{"worker":"fixture","scanId":"scan","lease":"lease"}`))
	r.Header.Set("Authorization", "Bearer fixture-worker")
	response := httptest.NewRecorder()
	s.handle(response, r)
	if response.Code != 409 {
		t.Fatal("expired lease resurrected", response.Code)
	}
}

func TestTakeoverChecksRespectConcurrencyAndKeepPartialResults(t *testing.T) {
	var active, peak atomic.Int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	go func() { <-started; <-started; close(release) }()
	checks := func(ctx context.Context, host string) (*SubdomainTakeover, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if host == "broken.owned.example" {
			return nil, context.DeadlineExceeded
		}
		return &SubdomainTakeover{Subdomain: host}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results, err := evaluateTakeovers(ctx, Scan{Concurrency: 2}, []string{"a.owned.example", "broken.owned.example", "b.owned.example"}, checks)
	if peak.Load() != 2 || len(results) != 2 || err == nil {
		t.Fatal("bounded DNS checks lost results or ignored errors", peak.Load(), results, err)
	}
}

func TestDetectionBatchesResumeConfirmedCoverage(t *testing.T) {
	w := Worker{Templates: "templates"}
	manifest, err := w.manifest()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, entry := range manifest.Templates {
		ids[entry.File] = entry.ID
	}
	var active, peak, calls atomic.Int32
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	go func() { <-started; <-started; <-started; close(release) }()
	var seenMu sync.Mutex
	seen := map[string]bool{}
	firstPass := true
	w.scannerCommand = func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		if name != "nuclei" {
			return nil, "", fmt.Errorf("unexpected scanner %s", name)
		}
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if firstPass {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
		}
		flags := map[string]string{}
		for i := 0; i+1 < len(args); i++ {
			flags[args[i]] = args[i+1]
		}
		rate, _ := strconv.Atoi(flags["-rl"])
		concurrency, _ := strconv.Atoi(flags["-bs"])
		maxRate, maxConcurrency := 6, 4
		if firstPass {
			maxRate, maxConcurrency = 2, 1
		}
		if rate > maxRate || concurrency > maxConcurrency {
			return nil, "", fmt.Errorf("aggregate scanner limits exceeded")
		}
		input, e := os.ReadFile(flags["-l"])
		if e != nil {
			return nil, "", e
		}
		urls := strings.Fields(string(input))
		if len(urls) > 50 {
			return nil, "", errors.New("unbounded detection batch")
		}
		var output []byte
		for i, raw := range urls {
			seenMu.Lock()
			seen[raw] = true
			seenMu.Unlock()
			for _, file := range strings.Split(flags["-t"], ",") {
				row, _ := json.Marshal(map[string]any{"template-id": ids[filepath.Base(file)], "url": raw, "response": "HTTP/1.1 200 OK\r\n", "matcher-status": false})
				output = append(output, append(row, '\n')...)
			}
			if firstPass && raw == "https://h00.owned.example" && i == 0 {
				return output, "", context.DeadlineExceeded
			}
		}
		return output, "", nil
	}
	cp := Checkpoint{}
	for i := 0; i < 25; i++ {
		cp.Assets = append(cp.Assets, Asset{Host: fmt.Sprintf("h%02d.owned.example", i), URL: fmt.Sprintf("https://h%02d.owned.example", i)})
	}
	claim := Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Concurrency: 4, Rate: 6}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cp, _, err = w.detect(ctx, claim, cp, "", t.TempDir())
	if err == nil || peak.Load() != 3 || len(cp.ServiceCoverage) != 17 || calls.Load() != 3 {
		t.Fatal("partial batch coverage incorrect", err, peak.Load(), len(cp.ServiceCoverage), calls.Load())
	}
	firstPass = false
	seen = map[string]bool{}
	cp, _, err = w.detect(ctx, claim, cp, "", t.TempDir())
	if err != nil || len(cp.ServiceCoverage) != 25 || len(seen) != 8 || seen["https://h00.owned.example"] {
		t.Fatal("resume repeated confirmed services or lost coverage", err, len(cp.ServiceCoverage), seen)
	}
}

func TestNucleiParallelismStaysWithinScanBudget(t *testing.T) {
	for _, sc := range []Scan{{Rate: 1, Concurrency: 1}, {Rate: 6, Concurrency: 4}, {Rate: 20, Concurrency: 5}, {Rate: 30, Concurrency: 10}} {
		workers := detectionWorkers(sc)
		rate, c, bs := nucleiParallelism(sc, workers, 7)
		if workers*rate > sc.Rate || workers*c*bs > max(workers, sc.Concurrency) || c < 1 || bs < 1 {
			t.Fatal("aggregate scanner budget exceeded", sc, workers, rate, c, bs)
		}
	}
}

func TestSplitDetectionBatches(t *testing.T) {
	urls := make([]string, 25)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://h%02d.owned.example", i)
	}
	batches := splitDetectionBatches(urls, 3)
	if len(batches) != 3 || len(batches[0]) != 9 || len(batches[2]) != 7 {
		t.Fatal(len(batches), batches)
	}
	if got := splitDetectionBatches(make([]string, 400), 3); len(got[0]) != 50 {
		t.Fatal("batch size not capped", len(got[0]))
	}
}

func TestCheckpointRetriesTransientErrorsButRejectsLostLease(t *testing.T) {
	for _, status := range []int{503, 409} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					http.Error(w, "fixture", status)
					return
				}
				w.WriteHeader(200)
			}))
			defer api.Close()
			w := Worker{API: api.URL, client: api.Client()}
			err := w.checkpoint(context.Background(), Claim{Scan: Scan{Stages: []Stage{{Name: "Detection"}}}}, "Detection", Checkpoint{}, "fixture")
			if status == 503 && (err != nil || calls.Load() != 2) {
				t.Fatal("transient checkpoint not retried", err, calls.Load())
			}
			if status == 409 && (err == nil || calls.Load() != 1) {
				t.Fatal("lost lease retried", err, calls.Load())
			}
		})
	}
}

func TestStageBudgetsUseWorkloadAndReserveCommitTime(t *testing.T) {
	cp := Checkpoint{}
	for i := 0; i < 25; i++ {
		cp.Assets = append(cp.Assets, Asset{Host: fmt.Sprintf("h%d.owned.example", i), URL: fmt.Sprintf("https://h%d.owned.example", i)})
	}
	serial := crawlStageTimeout(cp, Scan{Concurrency: 1, Rate: 10})
	parallel := crawlStageTimeout(cp, Scan{Concurrency: 5, Rate: 10})
	if parallel >= serial {
		t.Fatal("crawl budget ignores concurrency", serial, parallel)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sc := Scan{Stages: []Stage{{Name: "Port discovery"}, {Name: "Normalization"}}}
	budget := scanStageBudget(ctx, sc, 0, cp)
	if budget > 35*time.Second || budget <= 30*time.Second {
		t.Fatal("downstream commit reserve missing", budget)
	}
}

func TestIncompleteStageMakesScanPartialAndResumesEarliestStage(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "fixture-worker")
	s := testServer(t)
	s.state = emptyState()
	s.allowUnverified, s.liveEnabled = true, true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Scans = []Scan{{ID: "scan", TargetID: "target", Domain: "owned.example", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Stages: []Stage{{Name: "Discovery", Status: "completed"}, {Name: "DNS resolution", Status: "completed"}}, Checkpoint: Checkpoint{IncompleteStages: map[string]string{"Discovery": "provider timed out"}}}}
	r := httptest.NewRequest("POST", "/internal/complete", strings.NewReader(`{"worker":"fixture","scanId":"scan","lease":"lease"}`))
	r.Header.Set("Authorization", "Bearer fixture-worker")
	response := httptest.NewRecorder()
	s.handle(response, r)
	if response.Code != 200 || s.state.Scans[0].Status != "partial" || !strings.Contains(s.state.Scans[0].Error, "Discovery") {
		t.Fatalf("incomplete stage claimed successful: %d %s", response.Code, response.Body.String())
	}
	response = request(s, "POST", "/api/scans/scan/retry", `{}`)
	if response.Code != 200 || s.state.Scans[0].Stages[0].Status != "pending" || s.state.Scans[1].Status != "partial" {
		t.Fatal("resume skipped failed discovery or changed history", response.Body.String())
	}
}

func TestDiscoveryRetainsRecordsAndRootAfterFailure(t *testing.T) {
	w := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		return []byte("{\"host\":\"app.owned.example\",\"source\":\"fixture\"}\n{\"host\":"), "", context.DeadlineExceeded
	}}
	cp, _, err := w.discover(context.Background(), Claim{Target: Target{Domain: "owned.example"}}, Checkpoint{Known: []string{"old.owned.example"}}, "", t.TempDir())
	if !errors.Is(err, context.DeadlineExceeded) || cp.Hosts["app.owned.example"] == nil || cp.Hosts["owned.example"] == nil || cp.Hosts["old.owned.example"] == nil {
		t.Fatal("partial discovery lost observations or fallback inventory", err, cp.Hosts)
	}
}

func TestDNSRetainsRecordsAfterProcessDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		return []byte("{\"host\":\"owned.example\",\"a\":[\"1.1.1.1\"]}\n{\"host\":"), "", context.DeadlineExceeded
	}}
	cp, _, err := w.resolve(ctx, Claim{Target: Target{Domain: "owned.example"}}, Checkpoint{Hosts: map[string][]string{"owned.example": {"fixture"}}}, t.TempDir())
	if !errors.Is(err, context.DeadlineExceeded) || len(cp.Assets) != 1 || cp.Assets[0].IP != "1.1.1.1" {
		t.Fatal("partial DNS output lost", err, cp)
	}
}

func TestCrawlCheckpointFailureIsReturnedWithObservations(t *testing.T) {
	var writes atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		http.Error(w, "storage unavailable", 503)
	}))
	defer api.Close()
	w := Worker{API: api.URL, client: api.Client(), scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		return []byte("{\"request\":{\"endpoint\":\"https://owned.example/app.js\"},\"response\":{\"status_code\":200}}\n"), "", nil
	}}
	cp, _, err := w.crawl(context.Background(), Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Stages: []Stage{{Name: "Endpoint crawling"}}}}, Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example"}}}, "", t.TempDir())
	if err == nil || writes.Load() == 0 || len(cp.Assets[0].Endpoints) != 1 {
		t.Fatal("checkpoint failure ignored or observations discarded", err, cp)
	}
}

func TestConcurrentCrawlCancellationDrainsObservations(t *testing.T) {
	started := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := Worker{scannerCommand: func(ctx context.Context, _ string, args []string, _, _ string) ([]byte, string, error) {
		started <- struct{}{}
		<-ctx.Done()
		row, _ := json.Marshal(map[string]any{"request": map[string]string{"endpoint": args[1] + "/seen"}, "response": map[string]int{"status_code": 200}})
		return append(row, '\n'), "", ctx.Err()
	}}
	go func() { <-started; <-started; cancel() }()
	cp, _, err := w.crawl(ctx, Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Concurrency: 2, Rate: 20}}, Checkpoint{Assets: []Asset{{Host: "a.owned.example", URL: "https://a.owned.example"}, {Host: "b.owned.example", URL: "https://b.owned.example"}}}, "", t.TempDir())
	if !errors.Is(err, context.Canceled) || len(cp.CrawlResults) != 0 || len(cp.Assets[0].Endpoints)+len(cp.Assets[1].Endpoints) != 2 {
		t.Fatal("cancellation lost observations or marked seeds clean", err, cp)
	}
}

func TestStageFindingSummaryListsOnlyNewFindings(t *testing.T) {
	cp := Checkpoint{Findings: []Finding{{Title: "old"}}}
	if got := stageFindingSummary("Detection", 1, cp); got != "[Findings] Detection: no new findings (1 total)." {
		t.Fatal(got)
	}
	for i := 0; i < 12; i++ {
		cp.Findings = append(cp.Findings, Finding{Title: fmt.Sprintf("f%d", i), Severity: "high", Host: "a.owned.example"})
	}
	got := stageFindingSummary("Detection", 1, cp)
	if !strings.HasPrefix(got, "[Findings] Detection: 12 new (13 total).") || !strings.Contains(got, "- f0 (high) on a.owned.example") || strings.Contains(got, "old") || !strings.Contains(got, "2 more in Findings") {
		t.Fatal(got)
	}
}

func TestStreamLinesBoundsLinesAndDropsTornTail(t *testing.T) {
	var input bytes.Buffer
	for i := 0; i < 20000; i++ { // ~5 MiB total: above the old aggregate cap
		input.WriteString(`{"template-id":"x","pad":"` + strings.Repeat("a", 240) + `"}` + "\n")
	}
	input.WriteString(strings.Repeat("b", 3<<20) + "\n") // oversized line
	input.WriteString(`{"template-id":"torn"`)           // killed mid-record
	count := 0
	dropped, err := streamLines(&input, 2<<20, func(line []byte) error { count++; return nil })
	if err != nil || count != 20000 || dropped != 1 {
		t.Fatal(count, dropped, err)
	}
}
