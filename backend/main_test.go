package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	return &Server{state: seed(true), file: filepath.Join(t.TempDir(), "state.json"), ctx: context.Background()}
}
func request(s *Server, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handle(w, r)
	return w
}
func TestDomainScope(t *testing.T) {
	for _, d := range []string{"localhost", "com", "co.uk", "github.io", "tenant.github.io", "127.0.0.1", "https://acme.com", "evil.com/path", "bad-.com", "a..com", "foo.vercel.app"} {
		if validDomain(d) {
			t.Errorf("unsafe root accepted: %s", d)
		}
	}
	for _, d := range []string{"acme.com", "company.co.uk", "company.dev"} {
		if !validDomain(d) {
			t.Errorf("valid root rejected: %s", d)
		}
	}
}
func TestTargetToken(t *testing.T) {
	s := testServer(t)
	w := request(s, "POST", "/api/targets", `{"domain":"company.com"}`)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var target Target
	_ = json.Unmarshal(w.Body.Bytes(), &target)
	if target.Status != "pending" || len(strings.TrimPrefix(target.Token, "surfacer-verification=")) != 32 {
		t.Fatal("token or status invalid")
	}
	if request(s, "POST", "/api/targets", `{"domain":"company.com"}`).Code != 409 {
		t.Fatal("duplicate accepted")
	}
	if request(s, "POST", "/api/scans", `{"targetId":"`+target.ID+`"}`).Code != 403 {
		t.Fatal("unverified scan accepted")
	}
}
func TestLiveScanFailsClosed(t *testing.T) {
	s := testServer(t)
	s.state.Targets = append(s.state.Targets, Target{ID: "live", Domain: "company.com", Status: "verified"})
	if request(s, "POST", "/api/scans", `{"targetId":"live"}`).Code != 503 {
		t.Fatal("live scanner must fail closed")
	}
}
func TestScanCancelAndPause(t *testing.T) {
	s := testServer(t)
	s.liveEnabled = true
	for i := range s.state.Targets {
		s.state.Targets[i].Demo = false
		s.state.Targets[i].Schedule = "Manual"
	}
	s.lookupTXT = func(ctx context.Context, host string) ([]string, error) {
		return []string{"surfacer-verification=demo-only"}, nil
	}
	w := request(s, "POST", "/api/scans", `{"targetId":"target-acme"}`)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var scan Scan
	_ = json.Unmarshal(w.Body.Bytes(), &scan)
	if request(s, "POST", "/api/scans", `{"targetId":"target-acme"}`).Code != 409 {
		t.Fatal("duplicate running scan accepted")
	}
	w = request(s, "POST", "/api/scans/"+scan.ID+"/cancel", `{}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	s.tick()
	if s.state.Scans[0].Status != "canceled" {
		t.Fatal("cancel not retained")
	}
	s.state.Settings.Paused = true
	if request(s, "POST", "/api/scans", `{"targetId":"target-acme-cloud"}`).Code != 409 {
		t.Fatal("kill switch bypassed")
	}
}
func TestTriageAndEvidence(t *testing.T) {
	s := testServer(t)
	if request(s, "PATCH", "/api/findings/f1", `{"status":"resolved","note":"Please close"}`).Code != 400 {
		t.Fatal("manual resolution accepted")
	}
	if request(s, "PATCH", "/api/findings/f1", `{"status":"accepted risk","note":""}`).Code != 400 {
		t.Fatal("empty note accepted")
	}
	w := request(s, "PATCH", "/api/findings/f1", `{"status":"accepted risk","note":"<script>alert(1)</script>"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if s.state.Findings[0].Status != "accepted risk" || len(s.state.Findings[0].Notes) != 1 {
		t.Fatal("decision not stored")
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("HTML output not escaped")
	}
	if strings.Contains(s.state.Findings[0].Evidence, "DATABASE_PASSWORD=secret") {
		t.Fatal("sample secret exposed")
	}
}
func TestLimitsAndPersistence(t *testing.T) {
	s := testServer(t)
	w := request(s, "PATCH", "/api/settings", `{"name":"Acme","rate":31,"concurrency":5,"retention":90,"paused":false}`)
	if w.Code != 400 {
		t.Fatal("rate cap bypassed")
	}
	w = request(s, "PATCH", "/api/settings", `{"name":"Team","rate":10,"concurrency":2,"retention":30,"paused":false}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	b, err := os.ReadFile(s.file)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err = json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Settings.Name != "Team" || len(st.Audit) < 5 {
		t.Fatal("persistence or audit failed")
	}
}
func TestFailedPersistenceRollsBack(t *testing.T) {
	s := testServer(t)
	s.file = "/dev/null/nope.json"
	w := request(s, "POST", "/api/targets", `{"domain":"company.com"}`)
	if w.Code != 500 {
		t.Fatal("expected persistence error")
	}
	if len(s.state.Targets) != 3 {
		t.Fatal("mutation not rolled back")
	}
}
func TestAuth(t *testing.T) {
	t.Setenv("API_TOKEN", "test-token")
	s := testServer(t)
	if request(s, "GET", "/api/state", "").Code != 401 {
		t.Fatal("unauthorized request accepted")
	}
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	s.handle(w, r)
	if w.Code != 200 {
		t.Fatal("authorized request rejected")
	}
}
func TestSchedulerCannotFabricateResults(t *testing.T) {
	s := testServer(t)
	s.state.Scans = []Scan{newScan(s.state.Targets[0], "Manual", 20)}
	for i := 0; i < 16; i++ {
		s.tick()
	}
	if s.state.Scans[0].Status != "queued" || s.state.Scans[0].Progress != 0 {
		t.Fatal("scheduler fabricated scan progress")
	}
	if s.state.Findings[0].Status != "open" {
		t.Fatal("scheduler changed findings without worker results")
	}
}

func TestLegacySamplesRemovedPreservesRealRecords(t *testing.T) {
	s := seed(true)
	s.Targets = append(s.Targets, Target{ID: "real", Domain: "company.com"})
	s.Assets = append(s.Assets, Asset{ID: "real-asset", TargetID: "real", Host: "company.com"})
	s.Findings = append(s.Findings, Finding{ID: "real-finding", TargetID: "real", Host: "company.com"})
	s.Audit = append(s.Audit, Event{ID: "real-audit", Title: "Target added", Detail: "company.com", Actor: "Workspace owner"})
	s.removeLegacySamples()
	if len(s.Targets) != 1 || len(s.Assets) != 1 || len(s.Findings) != 1 || len(s.Scans) != 0 || len(s.Events) != 0 || len(s.Audit) != 1 {
		t.Fatalf("legacy cleanup lost real data or retained samples: %+v", s)
	}
}

func TestDNSVerificationAndRevocation(t *testing.T) {
	s := testServer(t)
	s.state.Targets = append(s.state.Targets, Target{ID: "dns", Domain: "company.com", Status: "pending", Token: "surfacer-verification=" + id(), Schedule: "Manual"})
	token := s.state.Targets[3].Token
	s.lookupTXT = func(ctx context.Context, host string) ([]string, error) {
		if host != "_surfacer.company.com" {
			t.Fatalf("wrong record name: %s", host)
		}
		return []string{"unrelated-record", token}, nil
	}
	if w := request(s, "POST", "/api/targets/dns/verify", `{}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if s.state.Targets[3].Status != "verified" {
		t.Fatal("matching TXT proof did not verify")
	}
	s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{token + "wrong"}, nil }
	if request(s, "POST", "/api/targets/dns/verify", `{}`).Code != 422 {
		t.Fatal("incorrect token accepted")
	}
	if s.state.Targets[3].Status != "paused" {
		t.Fatal("lost proof did not pause target")
	}
}

func TestCrossOriginRejected(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "http://localhost:8080/api/scans", strings.NewReader(`{"targetId":"target-acme"}`))
	r.Header.Set("Origin", "https://external.example")
	w := httptest.NewRecorder()
	s.handle(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin write accepted")
	}
}

func TestKillSwitchCancelsAllActiveScans(t *testing.T) {
	s := testServer(t)
	s.state.Scans = []Scan{newScan(Target{ID: "real", Domain: "company.com"}, "Manual", 20)}
	w := request(s, "PATCH", "/api/settings", `{"name":"Acme","rate":20,"concurrency":5,"retention":90,"paused":true}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if s.state.Scans[0].Status != "canceled" {
		t.Fatal("kill switch did not cancel active scan")
	}
	s.tick()
	if s.state.Scans[0].Status != "canceled" {
		t.Fatal("canceled job resumed")
	}
}
