package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestServiceCoverageDoesNotResolveSiblingPort(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example"}}
	finding := Finding{ID: "finding", TargetID: "target", Host: "owned.example", Template: "git-config", MatchedAt: "https://owned.example:8443/.git/config", Status: "open"}
	s.state.Findings = []Finding{finding}
	sc := Scan{TargetID: "target", Checkpoint: Checkpoint{Coverage: map[string][]string{"owned.example": {"git-config"}}, ServiceCoverage: map[string][]string{"https://owned.example": {"git-config"}}}}
	s.normalize(&sc, true)
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "open" || s.state.Findings[0].MissingScans != 0 {
		t.Fatal("clean sibling service resolved untested port")
	}
	sc.Checkpoint.ServiceCoverage["https://owned.example:8443"] = []string{"git-config"}
	s.normalize(&sc, true)
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "resolved" {
		t.Fatal("two covered clean service scans did not resolve finding")
	}
}
func TestHistoricalScopeAndQueryPrivacy(t *testing.T) {
	cp := Checkpoint{History: []Endpoint{{URL: "https://owned.example/old", Historical: true}}}
	if err := validateCheckpoint(cp, "owned.example"); err != nil {
		t.Fatal(err)
	}
	cp.History[0].URL = "https://owned.example/old?secret=value"
	if validateCheckpoint(cp, "owned.example") == nil {
		t.Fatal("historical query values accepted")
	}
	cp.History[0].URL = "https://other.example/old"
	if validateCheckpoint(cp, "owned.example") == nil {
		t.Fatal("out-of-scope archive URL accepted")
	}
}

func TestLargePortWorkloadBudgetAndResume(t *testing.T) {
	cp := Checkpoint{DNS: map[string][]string{}, PortResults: map[string][]int{"1.1.1.1": {443}}}
	for i := 1; i <= 226; i++ {
		host := fmt.Sprintf("h%d.owned.example", i)
		cp.Assets = append(cp.Assets, Asset{Host: host})
		cp.DNS[host] = []string{fmt.Sprintf("1.1.1.%d", i)}
	}
	if portStageTimeout(cp, 20) != 40*time.Minute {
		t.Fatal("large workload still has seven-minute budget")
	}
	calls, seen := 0, map[string]bool{}
	w := Worker{scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		b, err := os.ReadFile(args[1])
		if err != nil {
			t.Fatal(err)
		}
		ips := strings.Fields(string(b))
		if len(ips) > portBatchSize {
			t.Fatal("unbounded port batch")
		}
		calls++
		out := ""
		for _, ip := range ips {
			if ip == "1.1.1.1" {
				t.Fatal("completed address rescanned")
			}
			if seen[ip] {
				t.Fatal("duplicate port target")
			}
			seen[ip] = true
			out += fmt.Sprintf("{\"ip\":\"%s\",\"port\":443}\n", ip)
		}
		return []byte(out), "", nil
	}}
	result, _, err := w.scanPorts(context.Background(), Claim{Proxy: "http://gateway:3128", Scan: Scan{Rate: 20}}, cp, t.TempDir())
	if err != nil || len(result.PortResults) != 226 || calls != 45 {
		t.Fatalf("resume failed: calls=%d results=%d error=%v", calls, len(result.PortResults), err)
	}
}
func TestPortDeadlineRetainsPositiveResults(t *testing.T) {
	cp := Checkpoint{DNS: map[string][]string{"owned.example": {"1.1.1.1"}}, Assets: []Asset{{Host: "owned.example"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	w := Worker{scannerCommand: func(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
		<-ctx.Done()
		return []byte(`{"ip":"1.1.1.1","port":443}`), "", ctx.Err()
	}}
	result, log, err := w.scanPorts(ctx, Claim{Proxy: "http://gateway:3128", Scan: Scan{Rate: 10}}, cp, t.TempDir())
	if err != nil || len(result.PortResults) != 0 || !contains(intStrings(result.Assets[0].Ports), "443") || len(result.PortIncomplete) == 0 || !strings.Contains(log, "incomplete") {
		t.Fatalf("deadline discarded results or claimed clean coverage: %s %v", log, err)
	}
}
func TestScannerTimeoutExplainsKill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, _, err := command(ctx, "sh", []string{"-c", "sleep 1"}, "", t.TempDir())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline hidden by signal killed: %v", err)
	}
}

func TestPartialScanRetryKeepsCheckpoints(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.allowUnverified = true
	s.liveEnabled = true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Scans = []Scan{{ID: "prior", TargetID: "target", Domain: "owned.example", Status: "partial", Attempts: 3, Stages: []Stage{{Name: "Discovery", Status: "completed"}, {Name: "DNS resolution", Status: "completed"}, {Name: "Port discovery", Status: "pending"}}, Checkpoint: Checkpoint{DNS: map[string][]string{"owned.example": {"1.1.1.1"}}, PortResults: map[string][]int{"1.1.1.1": {443}}}}}
	response := request(s, "POST", "/api/scans/prior/retry", `{}`)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	retry := s.state.Scans[0]
	if retry.ID == "prior" || retry.Status != "queued" || retry.Attempts != 0 || retry.Stages[0].Status != "completed" || retry.Stages[2].Status != "pending" || len(retry.Checkpoint.PortResults) != 1 {
		t.Fatal("retry discarded prior progress")
	}
	if s.state.Scans[1].Status != "partial" {
		t.Fatal("prior scan history changed")
	}
	if request(s, "POST", "/api/scans/prior/retry", `{}`).Code != 409 {
		t.Fatal("duplicate active retry allowed")
	}
}

func TestRetryReopensCompletedPartialPortStage(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.allowUnverified = true
	s.liveEnabled = true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Scans = []Scan{{ID: "prior", TargetID: "target", Domain: "owned.example", Status: "partial", Stages: []Stage{{Name: "Discovery", Status: "completed"}, {Name: "DNS resolution", Status: "completed"}, {Name: "Port discovery", Status: "completed"}, {Name: "HTTP probing", Status: "completed"}}, Checkpoint: Checkpoint{PortIncomplete: []string{"owned.example"}, DNS: map[string][]string{"owned.example": {"1.1.1.1"}}, Assets: []Asset{{Host: "owned.example", URL: "https://owned.example", Services: []Service{{URL: "https://owned.example", Port: 443}}}}, PortResults: map[string][]int{}}}}
	response := request(s, "POST", "/api/scans/prior/retry", `{}`)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	retry := s.state.Scans[0]
	if retry.Stages[2].Status != "pending" || retry.Stages[3].Status != "pending" || retry.Checkpoint.Assets[0].URL != "" || len(retry.Checkpoint.Assets[0].Services) != 0 || len(retry.Checkpoint.PortIncomplete) != 0 {
		t.Fatal("partial port retry reused stale downstream stages")
	}
}
