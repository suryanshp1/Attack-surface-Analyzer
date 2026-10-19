package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func recordDeletionFixture(t *testing.T) *Server {
	t.Helper()
	s := deletionFixture(t)
	s.state.Assets = []Asset{{ID: "asset", TargetID: "target-acme", Host: "acme.com", Endpoints: []Endpoint{{ID: "endpoint", URL: "https://acme.com/api"}}}}
	s.state.History = []Endpoint{{ID: "history", TargetID: "target-acme", URL: "https://acme.com/old", Historical: true}}
	s.state.Scans = []Scan{{ID: "finished", TargetID: "target-acme", Status: "completed"}, {ID: "active", TargetID: "target-acme", Status: "running"}}
	s.state.Hazards = []EndpointHazard{{ID: "hazard", URL: "https://acme.com/api", Parameter: "url", HazardClass: "ssrf_candidate"}}
	s.state.Takeovers = []SubdomainTakeover{{ID: "takeover", Subdomain: "sub.acme.com", ServiceProvider: "fixture", Status: "suppressed"}}
	return s
}

func TestRecordDeletionRolesValidationAndJSONPersistence(t *testing.T) {
	resources := map[string]string{"assets": "asset", "endpoints": "endpoint", "scans": "finished", "hazards": "hazard", "takeovers": "takeover"}
	for resource, id := range resources {
		for _, role := range []string{"viewer", "analyst", "owner"} {
			t.Run(resource+"/"+role, func(t *testing.T) {
				s, key := mcpFixture(t, role)
				t.Setenv("API_TOKEN", "bootstrap-fixture")
				fixture := recordDeletionFixture(t)
				s.state.Assets, s.state.History, s.state.Scans, s.state.Hazards, s.state.Takeovers = fixture.state.Assets, fixture.state.History, fixture.state.Scans, fixture.state.Hazards, fixture.state.Takeovers
				body := `{"ids":["` + id + `"]}`
				r := httptest.NewRequest("DELETE", "/api/"+resource, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+key)
				w := httptest.NewRecorder()
				s.handle(w, r)
				if role != "owner" {
					if w.Code != 403 || s.recordDeleted(resource, id) {
						t.Fatal("unauthorized deletion", w.Code)
					}
					return
				}
				if w.Code != 200 || !s.recordDeleted(resource, id) {
					t.Fatal(w.Code, w.Body.String())
				}
				if s.state.Audit[0].Actor != "Agent" || !strings.Contains(s.state.Audit[0].Detail, resource) {
					t.Fatal("missing deletion identity")
				}
				b, err := os.ReadFile(s.file)
				if err != nil {
					t.Fatal(err)
				}
				var stored State
				if err := json.Unmarshal(b, &stored); err != nil {
					t.Fatal(err)
				}
				if stored.RecordDeletions[resource+":"+id] == "" {
					t.Fatal("JSON reload lost deletion")
				}
			})
		}
	}
	t.Setenv("API_TOKEN", "")
	for resource, id := range resources {
		s := recordDeletionFixture(t)
		for _, body := range []string{`{"ids":["` + id + `","missing"]}`, `{"ids":["` + id + `","` + id + `"]}`, `{"ids":[]}`, `{"ids":["../x"]}`} {
			if w := request(s, "DELETE", "/api/"+resource, body); w.Code != 400 || s.recordDeleted(resource, id) {
				t.Fatal("non-atomic or invalid batch accepted", resource, w.Code)
			}
		}
	}
}

func TestRecordDeletionFiltersPublicAndMCPWithoutCascadingHistory(t *testing.T) {
	t.Setenv("API_TOKEN", "")
	s := recordDeletionFixture(t)
	for resource, ids := range map[string][]string{"assets": {"asset"}, "endpoints": {"endpoint", "history"}, "scans": {"finished"}, "hazards": {"hazard"}, "takeovers": {"takeover"}} {
		body, _ := json.Marshal(map[string]any{"ids": ids})
		if w := request(s, "DELETE", "/api/"+resource, string(body)); w.Code != 200 {
			t.Fatal(resource, w.Body.String())
		}
	}
	out := s.publicState()
	if len(out.Assets) != 0 || len(out.History) != 0 || len(out.Hazards) != 0 || len(out.Takeovers) != 0 || len(out.Scans) != 1 || out.Scans[0].ID != "active" || out.RecordDeletions != nil {
		t.Fatal("public snapshot exposed deleted records or metadata")
	}
	if len(out.Findings) != 3 || len(s.state.Scans) != 2 || len(s.state.Assets[0].Endpoints) != 1 || s.state.Takeovers[0].Status != "suppressed" {
		t.Fatal("deletion cascaded into finding/scan/endpoint/triage history")
	}
	mcpServer, key := mcpFixture(t, "viewer")
	mcpServer.state.Assets, mcpServer.state.History, mcpServer.state.Scans = s.state.Assets, s.state.History, s.state.Scans
	mcpServer.state.RecordDeletions = s.state.RecordDeletions
	for tool, want := range map[string]float64{"list_assets": 0, "list_endpoints": 0, "list_scans": 1} {
		data := mcpStructured(t, mcpCall(t, mcpServer, key, tool, map[string]any{}))
		if data["total"] != want {
			t.Fatal(tool, data)
		}
	}
	if !mcpFailed(mcpCall(t, mcpServer, key, "get_scan", map[string]any{"scanId": "finished"})) {
		t.Fatal("get_scan exposed deleted run")
	}
}

func TestRecordDeletionRejectsActiveBatchAndRollsBackMetadata(t *testing.T) {
	t.Setenv("API_TOKEN", "")
	s := recordDeletionFixture(t)
	for _, status := range []string{"queued", "running", "retrying", "pending", "unknown", ""} {
		s.state.Scans[1].Status = status
		w := request(s, "DELETE", "/api/scans", `{"ids":["finished","active"]}`)
		if w.Code != 409 || s.recordDeleted("scans", "finished") {
			t.Fatal("active batch mutated history", status, w.Code)
		}
	}
	if err := os.WriteFile(s.file, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	s.file += "/state.json"
	before, _ := json.Marshal(s.state)
	if w := request(s, "DELETE", "/api/assets/asset", ""); w.Code != 500 {
		t.Fatal(w.Code)
	}
	after, _ := json.Marshal(s.state)
	if string(before) != string(after) {
		t.Fatal("failed save retained deletion metadata/audit")
	}
}

func TestRecordDeletionOnlyFreshScanRestoresObservations(t *testing.T) {
	s := recordDeletionFixture(t)
	assetID := fingerprint("target-acme", "acme.com")
	s.state.RecordDeletions = map[string]string{}
	for _, key := range []string{"assets:" + assetID, "endpoints:endpoint", "endpoints:history", "hazards:hazard", "takeovers:takeover", "scans:finished"} {
		s.state.RecordDeletions[key] = "2026-10-19T10:00:00Z"
	}
	sc := &Scan{TargetID: "target-acme", StartedAt: "2026-10-19T09:00:00Z", Checkpoint: Checkpoint{Assets: s.state.Assets, History: s.state.History, Hazards: s.state.Hazards, Takeovers: s.state.Takeovers}}
	s.restoreObservedRecords(sc)
	if len(s.state.RecordDeletions) != 6 {
		t.Fatal("existing scan restored deleted observations")
	}
	sc.StartedAt, sc.ParentScanID = "2026-10-19T11:00:00Z", "prior"
	s.restoreObservedRecords(sc)
	if len(s.state.RecordDeletions) != 6 {
		t.Fatal("recovery checkpoint restored deleted observations")
	}
	sc.ParentScanID = ""
	s.restoreObservedRecords(sc)
	if len(s.state.RecordDeletions) != 1 || !s.recordDeleted("scans", "finished") {
		t.Fatal("fresh observations not restored or scan history restored", s.state.RecordDeletions)
	}
}
