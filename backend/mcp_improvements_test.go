package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func mcpStructured(t *testing.T, response map[string]any) map[string]any {
	t.Helper()
	if mcpFailed(response) {
		t.Fatal("MCP call failed", response)
	}
	return response["result"].(map[string]any)["structuredContent"].(map[string]any)
}

func TestMCPResumeAndSingleScanPreserveCoverageAndPermissions(t *testing.T) {
	s, key := mcpFixture(t, "viewer")
	s.liveEnabled, s.allowUnverified = true, true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Scans = []Scan{{ID: "prior", TargetID: "target", Domain: "owned.example", Status: "partial", Lease: "private-lease", Checkpoint: Checkpoint{IncompleteStages: map[string]string{"Detection": "unfinished batch"}, CrawlResults: map[string]bool{"https://owned.example": true}, ServiceCoverage: map[string][]string{"https://owned.example": {"git-config"}}}, Stages: []Stage{{Name: "Discovery", Status: "completed"}, {Name: "Detection", Status: "completed", Log: "unfinished detection coverage"}}}}
	data := mcpStructured(t, mcpCall(t, s, key, "get_scan", map[string]any{"scanId": "prior"}))
	raw, _ := json.Marshal(data)
	if strings.Contains(string(raw), "private-lease") || strings.Contains(string(raw), "serviceCoverage") || !strings.Contains(string(raw), "crawlFinished") || !strings.Contains(string(raw), "partial") {
		t.Fatal("single scan leaked checkpoint or omitted coverage", string(raw))
	}
	if !mcpFailed(mcpCall(t, s, key, "resume_scan", map[string]any{"scanId": "prior"})) {
		t.Fatal("viewer resumed scan")
	}
	s.state.Members[0].Role = "analyst"
	s.state.Settings.Paused = true
	if !mcpFailed(mcpCall(t, s, key, "resume_scan", map[string]any{"scanId": "prior"})) {
		t.Fatal("pause bypassed")
	}
	s.state.Settings.Paused = false
	resumed := mcpStructured(t, mcpCall(t, s, key, "resume_scan", map[string]any{"scanId": "prior"}))
	if resumed["status"] != "queued" || len(s.state.Scans) != 2 || s.state.Scans[0].Stages[1].Status != "pending" || len(s.state.Scans[0].Checkpoint.ServiceCoverage) != 1 {
		t.Fatal("resume lost stage or service coverage", resumed)
	}
	if _, exposed := resumed["checkpoint"]; exposed {
		t.Fatal("resume exposed checkpoints")
	}
	if !mcpFailed(mcpCall(t, s, key, "resume_scan", map[string]any{"scanId": "prior"})) {
		t.Fatal("duplicate target scan allowed")
	}
	if !mcpFailed(mcpCall(t, s, key, "get_scan", map[string]any{"scanId": "missing"})) {
		t.Fatal("missing scan fabricated")
	}
	if s.state.Audit[0].Actor != "Agent" {
		t.Fatal("resume lost member audit identity")
	}
}

func TestMCPByteBoundedPaginationDoesNotSkipItems(t *testing.T) {
	s, key := mcpFixture(t, "viewer")
	s.state.Findings = nil
	notes := make([]Note, 150)
	for i := range notes {
		notes[i].Text = strings.Repeat("a", 2000)
	}
	for i := 0; i < 7; i++ {
		s.state.Findings = append(s.state.Findings, Finding{ID: fmt.Sprintf("f%d", i), TargetID: "target", Status: "open", Severity: "high", Notes: notes, EvidenceKey: "private-storage-key", Evidence: "PASSWORD=do-not-export"})
	}
	seen := map[string]bool{}
	offset := 0
	for page := 0; page < 4; page++ {
		data := mcpStructured(t, mcpCall(t, s, key, "list_findings", map[string]any{"limit": 100, "offset": offset, "status": "open", "severity": "high"}))
		raw, _ := json.Marshal(data)
		if len(raw) > 1<<20 || strings.Contains(string(raw), "private-storage-key") || strings.Contains(string(raw), "do-not-export") {
			t.Fatal("page exceeded budget or leaked evidence", len(raw))
		}
		for _, item := range data["items"].([]any) {
			id := item.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatal("duplicate page item", id)
			}
			seen[id] = true
		}
		if data["total"] != float64(7) {
			t.Fatal("total lost", data["total"])
		}
		next, more := data["nextOffset"]
		if !more {
			break
		}
		offset = int(next.(float64))
	}
	if len(seen) != 7 {
		t.Fatal("byte pagination skipped findings", seen)
	}
}

func TestMCPStrictInputsAndToolAnnotations(t *testing.T) {
	s, key := mcpFixture(t, "analyst")
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"list_scans", map[string]any{"status": "partial", "typo": true}},
		{"list_scans", map[string]any{"severity": "high"}},
		{"list_findings", map[string]any{"status": "not-a-status"}},
		{"list_targets", map[string]any{"targetId": "../../settings"}},
		{"get_scan", map[string]any{"scanId": "../../settings"}},
		{"resume_scan", map[string]any{}},
		{"triage_finding", map[string]any{"findingId": "f1", "status": "resolved", "note": "invalid resolution"}},
	} {
		if !mcpFailed(mcpCall(t, s, key, tc.name, tc.args)) {
			t.Fatal("invalid tool arguments accepted", tc)
		}
	}
	w := mcpHTTP(s, key, "POST", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "")
	var response struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				Annotations map[string]any `json:"annotations"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Result.Tools) != 10 {
		t.Fatal("missing tools")
	}
	for _, tool := range response.Result.Tools {
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatal("tool accepts unknown arguments", tool.Name)
		}
		read := strings.HasPrefix(tool.Name, "list_") || tool.Name == "get_scan"
		if read && (tool.Annotations["readOnlyHint"] != true || tool.Annotations["openWorldHint"] != false) {
			t.Fatal("read annotations incorrect", tool)
		}
		if tool.Name == "resume_scan" && (tool.Annotations["openWorldHint"] != true || tool.Annotations["destructiveHint"] != false) {
			t.Fatal("resume annotations incorrect", tool)
		}
	}
}
