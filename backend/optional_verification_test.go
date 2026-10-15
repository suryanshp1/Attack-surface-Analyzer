package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOptionalVerificationAllowsFullScanFlow(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "worker-test-token")
	s := testServer(t)
	s.state = emptyState()
	s.state.Targets = []Target{{ID: "target", Domain: "company.com", Status: "pending", Token: "unused-proof", Schedule: "Manual"}}
	s.allowUnverified = true
	s.liveEnabled = true
	s.gatewaySecret = "test-permit-secret"
	s.lookupTXT = func(context.Context, string) ([]string, error) {
		t.Fatal("optional mode must not query ownership DNS")
		return nil, nil
	}
	w := request(s, "POST", "/api/scans", `{"targetId":"target"}`)
	if w.Code != 201 {
		t.Fatalf("scan queue rejected: %d %s", w.Code, w.Body.String())
	}
	workerRequest := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer worker-test-token")
		w := httptest.NewRecorder()
		s.workerAPI(w, r)
		return w
	}
	w = workerRequest("/internal/claim", `{"worker":"test-worker"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var claim Claim
	if err := json.Unmarshal(w.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.Scan.ID == "" || claim.Permit == "" {
		t.Fatalf("no scan claimed: %s", w.Body.String())
	}
	payload, _ := json.Marshal(map[string]any{"worker": "test-worker", "permit": claim.Permit})
	if w = workerRequest("/internal/authorize", string(payload)); w.Code != 200 {
		t.Fatalf("gateway rejected optional target: %s", w.Body.String())
	}
	payload, _ = json.Marshal(map[string]any{"worker": "test-worker", "scanId": claim.Scan.ID, "lease": claim.Scan.Lease, "stage": 0, "status": "running"})
	if w = workerRequest("/internal/stage", string(payload)); w.Code != 200 {
		t.Fatalf("stage rejected optional target: %s", w.Body.String())
	}
	s.state.Targets[0].Status = "verified"
	s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{"wrong-proof"}, nil }
	if w = request(s, "POST", "/api/targets/target/verify", `{}`); w.Code != 422 || s.state.Scans[0].Status != "running" {
		t.Fatal("optional verification failure canceled a scan")
	}
	s.lookupTXT = func(context.Context, string) ([]string, error) {
		t.Fatal("optional mode must not recheck DNS")
		return nil, nil
	}
	s.reverifyOwnedTargets()
	pub := s.publicState()
	if pub.Runtime.VerificationRequired || !pub.Targets[0].CanScan || pub.Targets[0].Status != "pending" || pub.Targets[0].LastVerified != "" {
		t.Fatal("optional mode fabricated verification or hid eligibility")
	}
	s.state.Settings.Paused = true
	if w = request(s, "POST", "/api/scans", `{"targetId":"target"}`); w.Code != 409 {
		t.Fatal("optional verification bypassed kill switch")
	}
	payload, _ = json.Marshal(map[string]any{"worker": "test-worker", "permit": claim.Permit})
	if w = workerRequest("/internal/authorize", string(payload)); w.Code != 403 {
		t.Fatal("paused workspace allowed gateway traffic")
	}
}

func TestOptionalVerificationSchedulesPendingTargets(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.allowUnverified = true
	s.liveEnabled = true
	s.state.Targets = []Target{{ID: "target", Domain: "company.com", Status: "pending", Schedule: "Daily"}}
	s.tick()
	s.tick()
	if len(s.state.Scans) != 1 || s.state.Scans[0].Status != "queued" {
		t.Fatal("pending target schedule missing or duplicated")
	}
	s.allowUnverified = false
	if s.publicState().Targets[0].CanScan {
		t.Fatal("required mode exposed an unverified target as eligible")
	}
}
