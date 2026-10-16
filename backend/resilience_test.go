package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNonFatalPortScanBatchFailure(t *testing.T) {
	cp := Checkpoint{
		DNS: map[string][]string{
			"h1.owned.example": {"1.1.1.1"},
			"h2.owned.example": {"1.1.1.2"},
		},
		Assets: []Asset{
			{Host: "h1.owned.example"},
			{Host: "h2.owned.example"},
		},
	}
	calls := 0
	w := Worker{
		scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
			calls++
			if calls == 1 {
				// First batch fails with simulated command exit error
				return nil, "naabu error: connection refused", errors.New("exit status 1")
			}
			// Second batch succeeds
			return []byte(`{"ip":"1.1.1.2","port":443}`), "", nil
		},
	}
	result, logs, err := w.scanPorts(context.Background(), Claim{Proxy: "http://gateway:3128", Scan: Scan{Rate: 1}}, cp, t.TempDir())
	if err != nil {
		t.Fatalf("scanPorts returned fatal error on non-fatal batch failure: %v", err)
	}
	if len(result.SourceIssues) == 0 {
		t.Fatal("expected failure to be recorded in SourceIssues")
	}
	if len(result.PortIncomplete) == 0 {
		t.Fatal("expected failed IP host to be recorded in PortIncomplete")
	}
	_ = logs
}

func TestNonFatalTLSxFailure(t *testing.T) {
	cp := Checkpoint{
		DNS: map[string][]string{
			"h1.owned.example": {"1.1.1.1"},
		},
		Assets: []Asset{
			{Host: "h1.owned.example", Ports: []int{443}},
		},
	}
	w := Worker{}
	// assessTLS uses command() which executes tlsx; since tlsx is not installed in local test environment,
	// it fails with exec.LookPath error. Verify it returns nil error and logs to SourceIssues!
	result, logs, err := w.assessTLS(context.Background(), Claim{DNS: "1.1.1.1:53", Target: Target{Domain: "owned.example"}}, cp, t.TempDir())
	if err != nil {
		t.Fatalf("assessTLS returned fatal error: %v", err)
	}
	if len(result.SourceIssues) == 0 {
		t.Fatal("expected TLSx failure to be recorded in SourceIssues")
	}
	_ = logs
}

func TestNonFatalKatanaSeedFailure(t *testing.T) {
	cp := Checkpoint{
		Assets: []Asset{
			{Host: "owned.example", URL: "https://owned.example"},
			{Host: "api.owned.example", URL: "https://api.owned.example"},
		},
	}
	calls := 0
	w := Worker{
		scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
			calls++
			if calls == 1 {
				return nil, "katana seed error", errors.New("exit status 1")
			}
			return []byte(`{"request":{"endpoint":"https://api.owned.example/health","method":"GET"},"response":{"status_code":200}}`), "", nil
		},
	}
	result, log, err := w.crawl(context.Background(), Claim{Proxy: "http://gateway:3128", Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 10, Concurrency: 1}}, cp, "http://gateway:3128", t.TempDir())
	if err != nil {
		t.Fatalf("crawl returned fatal error: %v", err)
	}
	if len(result.SourceIssues) == 0 {
		t.Fatal("expected failed seed to be recorded in SourceIssues")
	}
	_ = log
}

func TestWorkerStageContinuation(t *testing.T) {
	stageCommitted := make(map[int]bool)
	completeCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		if r.URL.Path == "/internal/stage" {
			if stageVal, ok := p["stage"].(float64); ok {
				stageCommitted[int(stageVal)] = true
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		if r.URL.Path == "/internal/complete" {
			completeCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	w := &Worker{
		ID:     "test-worker",
		API:    server.URL,
		client: server.Client(),
		proxyLookup: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
			if name == "subfinder" {
				// Stage 0 (Discovery) fails with command error
				return nil, "subfinder crashed", errors.New("exit status 2")
			}
			return []byte(`{"host":"owned.example"}`), "", nil
		},
	}

	claim := Claim{
		Proxy:  "http://127.0.0.1:3128",
		Permit: "dummy-permit",
		Target: Target{Domain: "owned.example"},
		Scan: Scan{
			ID:     "scan-test",
			Domain: "owned.example",
			Lease:  "lease-test",
			Stages: []Stage{
				{Name: "Discovery", Status: "pending"},
				{Name: "Normalization", Status: "pending"},
			},
		},
	}

	w.execute(context.Background(), claim)

	if !stageCommitted[0] {
		t.Fatal("expected stage 0 to be committed")
	}
	if !stageCommitted[1] {
		t.Fatal("expected stage 1 to be executed and committed despite stage 0 failure")
	}
	if !completeCalled {
		t.Fatal("expected /internal/complete to be called after all stages finished")
	}
}

