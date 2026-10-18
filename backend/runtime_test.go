package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPrivateDestinationsBlocked(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.1.1", "172.17.0.2", "192.168.1.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "64:ff9b::a00:1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Errorf("private/metadata IP allowed: %s", ip)
		}
	}
	if !publicIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IP rejected")
	}
}
func TestDNSRebindingAndScopeGateway(t *testing.T) {
	called := false
	g := Gateway{Secret: "secret", authorize: func(context.Context, string) bool { return true }, lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}, dial: func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil }}
	if _, err := g.safeDial(context.Background(), "tcp", "owned.com:443"); err == nil || called {
		t.Fatal("mixed public/private resolution bypassed dial gate")
	}
	permit := signPermit(Permit{Scan: "scan", Root: "owned.com", Expires: time.Now().Add(time.Minute).Unix(), Lease: "fixture-lease"}, "secret")
	r := httptest.NewRequest("GET", "http://unowned.com/", nil)
	r.SetBasicAuth("scan", permit)
	r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))
	w := httptest.NewRecorder()
	g.serve(w, r)
	if w.Code != 403 {
		t.Fatal("out-of-scope proxy request accepted")
	}
}
func TestGatewayDualStackFallback(t *testing.T) {
	dialedOrder := []string{}
	pipeClient, pipeServer := net.Pipe()
	defer pipeServer.Close()
	defer pipeClient.Close()

	g := Gateway{
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("2606:4700:3036::ac43:b8fc"),
				netip.MustParseAddr("1.1.1.1"),
			}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedOrder = append(dialedOrder, address)
			if strings.HasPrefix(address, "1.1.1.1") {
				return pipeClient, nil
			}
			return nil, context.DeadlineExceeded
		},
	}
	conn, err := g.safeDial(context.Background(), "tcp", "owned.com:443")
	if err != nil {
		t.Fatalf("expected successful fallback, got: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection")
	}
	if len(dialedOrder) == 0 || !strings.HasPrefix(dialedOrder[0], "1.1.1.1") {
		t.Fatalf("expected IPv4 address to be dialed first, got order: %v", dialedOrder)
	}
}
func TestPermitTamperingAndExpiry(t *testing.T) {
	token := signPermit(Permit{Scan: "scan", Root: "owned.com", Expires: time.Now().Add(time.Minute).Unix(), Lease: "fixture-lease"}, "secret")
	if _, err := checkPermit(token, "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := checkPermit(token+"x", "secret"); err == nil {
		t.Fatal("tampered token accepted")
	}
	expired := signPermit(Permit{Scan: "scan", Root: "owned.com", Expires: time.Now().Add(-time.Minute).Unix(), Lease: "fixture-lease"}, "secret")
	if _, err := checkPermit(expired, "secret"); err == nil {
		t.Fatal("expired token accepted")
	}
}
func TestTwoSuccessfulCoveredScansResolve(t *testing.T) {
	s := testServer(t)
	s.state = seed(false)
	s.state.Targets = []Target{{ID: "target", Domain: "owned.com", Status: "verified"}}
	asset := Asset{Host: "owned.com", Type: "Web service", URL: "https://owned.com", Technologies: []string{}, Ports: []int{443}}
	finding := Finding{Host: "owned.com", Template: "git-config", MatchedAt: "https://owned.com/.git/config", Title: "Git exposed", Severity: "medium", Evidence: "PASSWORD=secret"}
	sc := Scan{ID: "one", TargetID: "target", Domain: "owned.com", Status: "completed", Checkpoint: Checkpoint{Assets: []Asset{asset}, Findings: []Finding{finding}}}
	s.normalize(&sc, true)
	if len(s.state.Findings) != 1 || strings.Contains(s.state.Findings[0].Evidence, "=secret") {
		t.Fatal("normalization/redaction failed")
	}
	sc.ID = "two"
	sc.Checkpoint.Findings = nil
	sc.Checkpoint.Coverage = map[string][]string{"owned.com": {"git-config"}}
	s.normalize(&sc, false)
	if s.state.Findings[0].MissingScans != 0 {
		t.Fatal("partial scan counted as clean")
	}
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "open" {
		t.Fatal("finding resolved after one clean scan")
	}
	sc.ID = "three"
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "resolved" {
		t.Fatal("finding did not resolve after two covered clean scans")
	}
	sc.Checkpoint.Findings = []Finding{finding}
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "open" || len(s.state.Findings) != 1 {
		t.Fatal("reopened finding duplicated")
	}
}
func TestCoverageNeverTransfersAcrossHosts(t *testing.T) {
	s := testServer(t)
	s.state = seed(false)
	s.state.Targets = []Target{{ID: "target", Domain: "owned.com", Status: "verified"}}
	s.state.Findings = []Finding{{ID: "finding", TargetID: "target", Host: "app.owned.com", Template: "apache-server-status", Status: "open"}}
	sc := Scan{TargetID: "target", Checkpoint: Checkpoint{Coverage: map[string][]string{"other.owned.com": {"apache-server-status"}, "app.owned.com": {"git-config"}}}}
	s.normalize(&sc, true)
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "open" {
		t.Fatal("coverage from another host resolved finding")
	}
}
func TestWorkerLeaseAndCheckpointRecovery(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "worker-secret")
	s := testServer(t)
	s.liveEnabled = true
	s.gatewaySecret = "gateway-secret"
	s.state = seed(false)
	target := Target{ID: "target", Domain: "owned.com", Status: "verified", Token: "proof", Schedule: "Manual"}
	s.state.Targets = []Target{target}
	s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{"proof"}, nil }
	sc := s.makeScan(target, "Manual")
	s.state.Scans = []Scan{sc}
	call := func(path string, p any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(p)
		r := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
		r.Header.Set("Authorization", "Bearer worker-secret")
		w := httptest.NewRecorder()
		s.handle(w, r)
		return w
	}
	w := call("/internal/claim", map[string]string{"worker": "worker-one"})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var claim Claim
	if err := json.Unmarshal(w.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.Scan.Status != "running" || claim.Scan.Lease == "" {
		t.Fatal("lease not created")
	}
	s.state.Scans[0].Stages[0].Status = "completed"
	s.state.Scans[0].Checkpoint.Hosts = map[string][]string{"owned.com": {"test"}}
	s.state.Scans[0].LeaseUntil = time.Now().Add(-time.Second).Format(time.RFC3339)
	s.maintenance()
	if s.state.Scans[0].Status != "queued" {
		t.Fatal("expired lease not recovered")
	}
	w = call("/internal/claim", map[string]string{"worker": "worker-two"})
	var resumed Claim
	_ = json.Unmarshal(w.Body.Bytes(), &resumed)
	if resumed.Scan.Stages[0].Status != "completed" || len(resumed.Scan.Checkpoint.Hosts) != 1 {
		t.Fatal("completed checkpoint was lost")
	}
	w = call("/internal/authorize", map[string]string{"worker": "egress-gateway", "permit": claim.Permit})
	if w.Code != 403 {
		t.Fatal("stale worker permit could reach targets after lease replacement")
	}
	w = call("/internal/authorize", map[string]string{"worker": "egress-gateway", "permit": resumed.Permit})
	if w.Code != 200 {
		t.Fatal("current worker permit rejected")
	}
	w = call("/internal/heartbeat", map[string]string{"worker": "worker-one", "scanId": sc.ID, "lease": claim.Scan.Lease})
	if w.Code != 409 {
		t.Fatal("stale worker could mutate scan")
	}
	s.state.Settings.Paused = true
	w = call("/internal/heartbeat", map[string]string{"worker": "worker-two", "scanId": sc.ID, "lease": resumed.Scan.Lease})
	if w.Code != 409 {
		t.Fatal("worker ignored kill switch")
	}
}
func TestCuratedTemplatesVerified(t *testing.T) {
	w := Worker{Templates: "templates"}
	m, err := w.manifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Templates) < 2 {
		t.Fatal("curated set missing")
	}
}
func TestSubprocessCancellation(t *testing.T) {
	if os.Getenv("SURFACER_NATIVE_TESTS") == "true" {
		t.Skip("separate native fixture suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := command(ctx, "sh", []string{"-c", "sleep 30"}, "", t.TempDir())
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatal("process tree was not canceled promptly")
	}
}

var _ = http.MethodGet

func TestMissingProbeRetainsLastObservedService(t *testing.T) {
	s := testServer(t)
	s.state = seed(false)
	s.state.Targets = []Target{{ID: "target", Domain: "owned.com", Status: "verified"}}
	sc := Scan{TargetID: "target", Checkpoint: Checkpoint{Assets: []Asset{{Host: "owned.com", URL: "https://owned.com", Type: "Web service", Ports: []int{443}, Status: 200, Technologies: []string{"Nginx"}}}}}
	s.normalize(&sc, true)
	sc.Checkpoint.Assets = []Asset{{Host: "owned.com", Type: "Domain", Ports: []int{}, Technologies: []string{}}}
	s.normalize(&sc, false)
	asset := s.state.Assets[0]
	if asset.URL != "https://owned.com" || len(asset.Ports) != 1 || !asset.Blocked {
		t.Fatal("missing response erased last observed service data")
	}
}
