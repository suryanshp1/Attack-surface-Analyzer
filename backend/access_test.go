package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMemberAccessLifecycle(t *testing.T) {
	t.Setenv("API_TOKEN", "test-owner")
	s := testServer(t)
	call := func(token, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.handle(w, r)
		return w
	}
	w := call("test-owner", "POST", "/api/members", `{"name":"Test viewer","role":"viewer"}`)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var created struct {
		Token  string
		Member Member
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	if created.Token == "" || s.state.AccessKeys[0].Hash == created.Token {
		t.Fatal("key was not hashed")
	}
	state := call(created.Token, "GET", "/api/state", "")
	if state.Code != 200 || strings.Contains(state.Body.String(), s.state.AccessKeys[0].Hash) || strings.Contains(state.Body.String(), created.Token) {
		t.Fatal("access secret exposed")
	}
	if call(created.Token, "PATCH", "/api/settings", `{"name":"Unauthorized"}`).Code != 403 {
		t.Fatal("viewer mutation allowed")
	}
	if call(created.Token, "POST", "/api/scans", `{}`).Code != 403 {
		t.Fatal("viewer scan allowed")
	}
	w = call("test-owner", "PATCH", "/api/members/"+created.Member.ID, `{"role":"analyst","enabled":true}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if call(created.Token, "POST", "/api/targets", `{"domain":"example.org"}`).Code != 403 {
		t.Fatal("analyst changed scope")
	}
	w = call(created.Token, "POST", "/api/api-keys", `{"name":"Automation","days":1}`)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if revoked := call("test-owner", "POST", "/api/api-keys/"+s.state.AccessKeys[0].ID+"/revoke", `{}`); revoked.Code != 200 {
		t.Fatal("revoke failed", revoked.Code, revoked.Body.String())
	}
	if call(created.Token, "GET", "/api/state", "").Code != 401 {
		t.Fatal("revoked key accepted")
	}
	s.state.AccessKeys[0].Revoked = false
	s.state.AccessKeys[0].ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	if call(created.Token, "GET", "/api/me", "").Code != 401 {
		t.Fatal("expired key accepted")
	}
}
func TestTCPAuthorizationBoundaries(t *testing.T) {
	s := testServer(t)
	s.allowUnverified = true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Scans = []Scan{{ID: "scan", TargetID: "target", Lease: "lease", Status: "running", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Checkpoint: Checkpoint{DNS: map[string][]string{"owned.example": {"1.1.1.1"}}}}}
	for _, v := range []struct {
		host, lease string
		port        int
		allowed     bool
	}{{"1.1.1.1", "lease", 443, true}, {"owned.example", "lease", 22, true}, {"127.0.0.1", "lease", 443, false}, {"8.8.8.8", "lease", 443, false}, {"other.example", "lease", 443, false}, {"owned.example", "wrong", 443, false}, {"owned.example", "lease", 6666, false}} {
		_, ok := s.tcpAuthorized("scan", v.lease, v.host, v.port)
		if ok != v.allowed {
			t.Fatalf("unexpected authorization for %s:%d", v.host, v.port)
		}
	}
	s.state.Settings.Paused = true
	if _, ok := s.tcpAuthorized("scan", "lease", "owned.example", 443); ok {
		t.Fatal("paused TCP scan accepted")
	}
}
