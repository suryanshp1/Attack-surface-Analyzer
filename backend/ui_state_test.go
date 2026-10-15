package main

import (
	"strings"
	"testing"
	"time"
)

func TestPublicAssessmentStateReconcilesLegacyStagesWithoutChangingCheckpoints(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.state.Scans = []Scan{{ID: "stopped", Status: "partial", Stages: []Stage{{Name: "Discovery", Status: "completed"}, {Name: "Endpoint crawling", Status: "running"}, {Name: "Detection", Status: "pending"}}, Checkpoint: Checkpoint{CrawlResults: map[string]bool{"https://owned.example": true}, CrawlIncomplete: []string{"https://b.owned.example"}, PortResults: map[string][]int{"1.1.1.1": {443}}}}, {ID: "active", Status: "running", Stages: []Stage{{Name: "Detection", Status: "running"}}}}
	out := s.publicState()
	if out.Scans[0].Stages[1].Status != "interrupted" || out.Scans[0].Stages[2].Status != "not_run" || out.Scans[1].Stages[0].Status != "running" {
		t.Fatal("scan and child stages contradict each other")
	}
	if out.Scans[0].Coverage.CrawlFinished != 1 || out.Scans[0].Coverage.CrawlRemaining != 1 || out.Scans[0].Coverage.PortFinished != 1 {
		t.Fatal("checkpoint coverage not exposed")
	}
	if s.state.Scans[0].Stages[1].Status != "running" || len(s.state.Scans[0].Checkpoint.CrawlResults) != 1 {
		t.Fatal("public presentation mutated stored history/checkpoints")
	}
	if len(out.Scans[0].Checkpoint.CrawlResults) != 0 {
		t.Fatal("private checkpoint exposed")
	}
}
func TestCertificateFindingSeparatesExpiredFromApproachingExpiry(t *testing.T) {
	for _, tc := range []struct {
		offset time.Duration
		title  string
	}{{-24 * time.Hour, "TLS certificate expired"}, {7 * 24 * time.Hour, "TLS certificate expiring soon"}} {
		expiry := time.Now().Add(tc.offset).UTC().Format(time.RFC3339)
		cp, _, err := tlsFindings(Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example", TLS: expiry}}})
		if err != nil || len(cp.Findings) != 1 || cp.Findings[0].Title != tc.title || !strings.Contains(cp.Findings[0].Description, "on ") {
			t.Fatalf("incorrect certificate condition: %#v", cp.Findings)
		}
		s := testServer(t)
		s.state = emptyState()
		legacy := cp.Findings[0]
		legacy.Title = "TLS certificate expiring soon"
		s.state.Findings = []Finding{legacy}
		if s.publicState().Findings[0].Title != tc.title {
			t.Fatal("historical certificate title misleading")
		}
		if s.state.Findings[0].Title != "TLS certificate expiring soon" {
			t.Fatal("reading public state rewrote history")
		}
	}
}
func TestPublicProbeObservationDistinguishesExclusionFromMissingResponse(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.state.Assets = []Asset{{Host: "private.owned.example", IP: "10.0.0.1", Blocked: true}, {Host: "web.owned.example", IP: "1.1.1.1", Ports: []int{443}}, {Host: "dns.owned.example", IP: "1.1.1.1"}, {Host: "responded.owned.example", IP: "1.1.1.1", Status: 502}}
	out := s.publicState()
	expected := []string{"Excluded · non-public address", "No HTTP response recorded", "Not probed", "HTTP 502"}
	for i, want := range expected {
		if out.Assets[i].ProbeStatus != want {
			t.Fatal(out.Assets[i].ProbeStatus, want)
		}
	}
}
