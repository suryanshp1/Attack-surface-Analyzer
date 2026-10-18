package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func mcpFixture(t *testing.T, role string) (*Server, string) {
	t.Helper()
	t.Setenv("API_TOKEN", "") // MCP must never inherit the development owner fallback.
	s := testServer(t)
	token := "surf_key_" + strings.Repeat("a", 64)
	s.state.Members = []Member{{ID: "agent", Name: "Agent", Role: role, Enabled: true}}
	s.state.AccessKeys = []AccessKey{{ID: "key", UserID: "agent", Hash: tokenDigest(token), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}
	return s, token
}
func mcpHTTP(s *Server, token, method, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost/api/mcp", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}
func TestMCPTransportAndAccess(t *testing.T) {
	s, key := mcpFixture(t, "viewer")
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`
	w := mcpHTTP(s, key, "POST", init, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"serverInfo"`) {
		t.Fatalf("initialize: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatal("stateless server assigned session")
	}
	t.Setenv("API_TOKEN", "bootstrap-owner")
	if w := mcpHTTP(s, "bootstrap-owner", "POST", init, ""); w.Code != 401 {
		t.Fatal("MCP accepted the internal API token")
	}
	t.Setenv("API_TOKEN", "")
	for _, token := range []string{"", "bootstrap-owner", "surf_key_" + strings.Repeat("b", 64)} {
		if w := mcpHTTP(s, token, "POST", init, ""); w.Code != 401 {
			t.Fatalf("invalid credential: %d", w.Code)
		}
	}
	for _, origin := range []string{"http://evil.example", "null", "http://localhost/path", "ftp://localhost"} {
		if w := mcpHTTP(s, key, "GET", "", origin); w.Code != 403 {
			t.Fatalf("unsafe origin %q: %d", origin, w.Code)
		}
	}
	if w := mcpHTTP(s, key, "GET", "", ""); w.Code != 405 {
		t.Fatalf("standalone SSE must be unavailable: %d", w.Code)
	}
	if w := mcpHTTP(s, key, "POST", init, "http://localhost"); w.Code != 200 {
		t.Fatalf("same origin: %d %s", w.Code, w.Body.String())
	}
	for _, invalidate := range []func(){func() { s.state.AccessKeys[0].Revoked = true }, func() {
		s.state.AccessKeys[0].Revoked = false
		s.state.AccessKeys[0].ExpiresAt = "2000-01-01T00:00:00Z"
	}, func() {
		s.state.AccessKeys[0].ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		s.state.Members[0].Enabled = false
	}} {
		invalidate()
		if w := mcpHTTP(s, key, "POST", init, ""); w.Code != 401 {
			t.Fatalf("inactive key: %d", w.Code)
		}
	}
}
func mcpCall(t *testing.T, s *Server, key, name string, args any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	w := mcpHTTP(s, key, "POST", string(raw), "")
	if w.Code != 200 {
		t.Fatalf("call %s: %d %s", name, w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}
func mcpFailed(response map[string]any) bool {
	if response["error"] != nil {
		return true
	}
	result, ok := response["result"].(map[string]any)
	return !ok || result["isError"] == true
}

func TestMCPToolsPermissionsAndCoverage(t *testing.T) {
	s, key := mcpFixture(t, "viewer")
	s.state.Scans = []Scan{{ID: "scan", TargetID: "target-acme", Status: "partial", Lease: "secret-lease", LeaseUntil: "secret-expiry", Checkpoint: Checkpoint{DNS: map[string][]string{"private.example": {"127.0.0.1"}}}}}
	listed := mcpCall(t, s, key, "list_scans", map[string]any{"limit": 1})
	raw, _ := json.Marshal(listed)
	if strings.Contains(string(raw), "secret-") || strings.Contains(string(raw), "127.0.0.1") || !strings.Contains(string(raw), "partial") {
		t.Fatal("scan coverage or private fields mishandled", string(raw))
	}
	targets := mcpCall(t, s, key, "list_targets", map[string]any{"limit": 1})
	raw, _ = json.Marshal(targets)
	if strings.Contains(string(raw), "surfacer-verification=") || !strings.Contains(string(raw), "nextOffset") {
		t.Fatal("verification token leaked or pagination lost", string(raw))
	}
	for _, kind := range []string{"targets", "assets", "findings", "endpoints", "scans"} {
		result := mcpCall(t, s, key, "list_"+kind, map[string]any{"limit": 1, "targetId": "absent"})
		r, ok := result["result"].(map[string]any)
		if !ok || r["isError"] == true {
			t.Fatal(result)
		}
		data := r["structuredContent"].(map[string]any)
		if data["total"] != float64(0) {
			t.Fatal("filter leaked other targets", data)
		}
	}
	denied := mcpCall(t, s, key, "start_scan", map[string]any{"targetId": "target-acme"})
	if denied["result"].(map[string]any)["isError"] != true {
		t.Fatal("viewer queued scan", denied)
	}
	s.state.Members[0].Role = "analyst"
	s.liveEnabled = true
	s.allowUnverified = true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Scans = nil
	s.state.Settings.Paused = true
	blocked := mcpCall(t, s, key, "start_scan", map[string]any{"targetId": "target"})
	if blocked["result"].(map[string]any)["isError"] != true || len(s.state.Scans) != 0 {
		t.Fatal("pause bypassed", blocked)
	}
	s.state.Settings.Paused = false
	started := mcpCall(t, s, key, "start_scan", map[string]any{"targetId": "target"})
	if started["result"].(map[string]any)["isError"] == true || len(s.state.Scans) != 1 {
		t.Fatal("scan not queued", started)
	}
	duplicate := mcpCall(t, s, key, "start_scan", map[string]any{"targetId": "target"})
	if duplicate["result"].(map[string]any)["isError"] != true || len(s.state.Scans) != 1 {
		t.Fatal("duplicate scan", duplicate)
	}
	canceled := mcpCall(t, s, key, "cancel_scan", map[string]any{"scanId": s.state.Scans[0].ID})
	if canceled["result"].(map[string]any)["isError"] == true || s.state.Scans[0].Status != "canceled" {
		t.Fatal("cancel failed", canceled)
	}
	if len(s.state.Audit) == 0 || s.state.Audit[0].Actor != "Agent" {
		t.Fatal("actor audit lost")
	}
	bad := mcpCall(t, s, key, "triage_finding", map[string]any{"findingId": "f1", "status": "resolved", "note": "Cannot resolve manually"})
	if !mcpFailed(bad) {
		t.Fatal("manual resolution allowed")
	}
	triaged := mcpCall(t, s, key, "triage_finding", map[string]any{"findingId": "f1", "status": "accepted risk", "note": "Documented risk decision"})
	if triaged["result"].(map[string]any)["isError"] == true {
		t.Fatal("triage failed", triaged)
	}
	for _, finding := range s.state.Findings {
		if finding.ID == "f1" && finding.Notes[len(finding.Notes)-1].Actor != "Agent" {
			t.Fatal("triage note lost member identity")
		}
	}
}
func TestMCPInputBounds(t *testing.T) {
	s, key := mcpFixture(t, "analyst")
	for _, args := range []map[string]any{{"offset": -1}, {"limit": 101}, {"offset": int(^uint(0) >> 1)}, {"limit": -1}} {
		result := mcpCall(t, s, key, "list_targets", args)
		if args["offset"] == int(^uint(0)>>1) {
			continue
		} // Huge valid offsets return an empty page without overflow.
		if !mcpFailed(result) {
			t.Fatal("invalid page accepted", result)
		}
	}
	result := mcpCall(t, s, key, "cancel_scan", map[string]any{"scanId": "../../settings"})
	if !mcpFailed(result) {
		t.Fatal("path traversal accepted")
	}
	w := mcpHTTP(s, key, "POST", strings.Repeat(" ", 32769), "")
	if w.Code < 400 {
		t.Fatal("oversized request accepted")
	}
	w = mcpHTTP(s, key, "POST", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "readOnlyHint") {
		t.Fatal("tools discovery failed", w.Body.String())
	}
}

type mcpAuthTransport struct{ key string }

func (t mcpAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+t.key)
	return http.DefaultTransport.RoundTrip(r)
}
func TestMCPRealClient(t *testing.T) {
	s, key := mcpFixture(t, "viewer")
	server := httptest.NewServer(http.HandlerFunc(s.handle))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + "/api/mcp", HTTPClient: &http.Client{Transport: mcpAuthTransport{key}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 10 {
		t.Fatalf("discovery: %v %v", tools, err)
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_targets", Arguments: map[string]any{"limit": 1}})
	if err != nil || result.IsError {
		t.Fatalf("call: %v %v", result, err)
	}
	s.mu.Lock()
	s.state.AccessKeys[0].Revoked = true
	s.mu.Unlock()
	if _, err := session.ListTools(ctx, nil); err == nil {
		t.Fatal("connected client survived revocation")
	}
}
