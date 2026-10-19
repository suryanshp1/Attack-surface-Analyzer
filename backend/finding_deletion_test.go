package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func deletionFixture(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	s.state.Findings = []Finding{
		{ID: "first", TargetID: "target-acme", Host: "acme.com", Status: "accepted risk", FirstSeen: "2025-01-01T00:00:00Z", Notes: []Note{{Text: "Keep this decision"}}, EvidenceKey: "retained"},
		{ID: "second", TargetID: "target-acme", Host: "acme.com", Status: "open", Severity: "high"},
		{ID: "third", TargetID: "other", Host: "other.example", Status: "open", Severity: "critical"},
	}
	s.state.Assets = []Asset{{TargetID: "target-acme", Host: "acme.com", Findings: 1, Severity: "high"}}
	return s
}

func TestFindingDeletionPersistsHistoryAndUpdatesPublicResults(t *testing.T) {
	t.Setenv("API_TOKEN", "")
	s := deletionFixture(t)
	w := request(s, "DELETE", "/api/findings", `{"ids":["first","second"]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":2`) {
		t.Fatal(w.Code, w.Body.String())
	}
	f := s.state.Findings[0]
	if f.DeletedAt == "" || f.Status != "accepted risk" || f.FirstSeen != "2025-01-01T00:00:00Z" || len(f.Notes) != 1 || f.EvidenceKey != "retained" {
		t.Fatal("deletion lost history", f)
	}
	public := s.publicState()
	if len(public.Findings) != 1 || public.Findings[0].ID != "third" || public.Assets[0].Findings != 0 || public.Assets[0].Severity != "none" {
		t.Fatal("deleted findings leaked into public snapshot/counts", public)
	}
	if s.state.Audit[0].Title != "Findings deleted" || s.state.Audit[0].Actor != "Workspace owner" || !strings.Contains(s.state.Audit[0].Detail, "first, second") {
		t.Fatal("deletion was not attributed/audited", s.state.Audit[0])
	}
	b, err := os.ReadFile(s.file)
	if err != nil {
		t.Fatal(err)
	}
	var stored State
	if err := json.Unmarshal(b, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Findings[0].DeletedAt != f.DeletedAt || len(stored.Findings[0].Notes) != 1 {
		t.Fatal("JSON persistence lost tombstone/history")
	}
	if w := request(s, "PATCH", "/api/findings/first", `{"status":"open","note":"Cannot edit deleted"}`); w.Code != 404 {
		t.Fatal("deleted finding was triaged", w.Code)
	}
	auditCount := len(s.state.Audit)
	if w := request(s, "DELETE", "/api/findings/first", ""); w.Code != 200 || len(s.state.Audit) != auditCount {
		t.Fatal("retry was not idempotent", w.Code)
	}
	w = request(s, "GET", "/api/metrics", "")
	if !strings.Contains(w.Body.String(), `surfacer_open_findings{severity="high"} 0`) {
		t.Fatal("deleted finding remained in metrics", w.Body.String())
	}
}

func TestFindingDeletionValidatesEntireBatchAndRollsBackSaveFailure(t *testing.T) {
	t.Setenv("API_TOKEN", "")
	for _, body := range []string{
		`{}`, `{"ids":[]}`, `{"ids":["first","missing"]}`, `{"ids":["first","first"]}`,
		`{"ids":["../settings"]}`, `{"ids":["first"],"all":true}`, `{"ids":["first"]} {}`,
	} {
		s := deletionFixture(t)
		before, _ := json.Marshal(s.state)
		if w := request(s, "DELETE", "/api/findings", body); w.Code != 400 {
			t.Fatal(body, w.Code, w.Body.String())
		}
		after, _ := json.Marshal(s.state)
		if string(before) != string(after) {
			t.Fatal("invalid batch mutated state", body)
		}
	}
	s := deletionFixture(t)
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = "first"
	}
	body, _ := json.Marshal(map[string]any{"ids": ids})
	if w := request(s, "DELETE", "/api/findings", string(body)); w.Code != 400 {
		t.Fatal(w.Code)
	}
	// A regular file cannot be used as a state directory.
	if err := os.WriteFile(s.file, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	s.file += "/state.json"
	before, _ := json.Marshal(s.state)
	if w := request(s, "DELETE", "/api/findings", `{"ids":["second"]}`); w.Code != 500 {
		t.Fatal(w.Code)
	}
	after, _ := json.Marshal(s.state)
	if string(before) != string(after) {
		t.Fatal("save failure did not roll back tombstone, counts and audit")
	}
}

func TestFindingDeletionRequiresOwnerAndMCPExcludesDeleted(t *testing.T) {
	for _, role := range []string{"viewer", "analyst", "owner"} {
		s, key := mcpFixture(t, role)
		t.Setenv("API_TOKEN", "bootstrap-fixture")
		s.state.Findings = []Finding{{ID: "finding", Status: "open"}}
		for _, path := range []string{"/api/findings", "/api/findings/finding"} {
			r := httptest.NewRequest("DELETE", path, strings.NewReader(`{"ids":["finding"]}`))
			r.Header.Set("Authorization", "Bearer "+key)
			w := httptest.NewRecorder()
			s.handle(w, r)
			want := 403
			if role == "owner" {
				want = 200
			}
			if w.Code != want {
				t.Fatal(role, path, w.Code, w.Body.String())
			}
		}
		if role == "owner" {
			data := mcpStructured(t, mcpCall(t, s, key, "list_findings", map[string]any{}))
			if data["total"] != float64(0) || len(data["items"].([]any)) != 0 {
				t.Fatal("MCP exposed deleted finding", data)
			}
		}
	}
}

func TestDeletedFindingReturnsOnlyFromFreshScanObservation(t *testing.T) {
	s := testServer(t)
	f := Finding{TargetID: "t", Host: "a.example", Template: "template", MatchedAt: "https://a.example/", Status: "accepted risk", FirstSeen: "2025-01-01T00:00:00Z", DeletedAt: "2026-10-19T10:00:00Z", Notes: []Note{{Text: "Retain"}}}
	f.ID = fingerprint(f.TargetID, f.Template, f.Host, f.MatchedAt)
	s.state.Findings = []Finding{f}
	observation := Finding{Host: f.Host, Template: f.Template, MatchedAt: f.MatchedAt, ScanID: "old"}
	sc := &Scan{ID: "old", TargetID: "t", StartedAt: "2026-10-19T09:00:00Z", Checkpoint: Checkpoint{Findings: []Finding{observation}}}
	s.publishScanFindings(sc, "2026-10-19T11:00:00Z")
	if s.state.Findings[0].DeletedAt == "" {
		t.Fatal("old scan replay undid deletion")
	}
	sc.ID, sc.StartedAt = "resumed", "2026-10-19T12:00:00Z"
	s.publishScanFindings(sc, "2026-10-19T12:01:00Z")
	if s.state.Findings[0].DeletedAt == "" {
		t.Fatal("retained checkpoint undid deletion")
	}
	sc.Checkpoint.Findings[0].ScanID = sc.ID
	s.publishScanFindings(sc, "2026-10-19T12:02:00Z")
	returned := s.state.Findings[0]
	if returned.DeletedAt != "" || returned.Status != f.Status || returned.FirstSeen != f.FirstSeen || len(returned.Notes) != 1 {
		t.Fatal("fresh scan did not restore finding with prior triage/history", returned)
	}
}
