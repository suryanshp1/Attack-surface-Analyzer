package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// This fixture is only compiled into the test executable. Production has no private-IP bypass.
func TestNativeScannerPipeline(t *testing.T) {
	if os.Getenv("SURFACER_NATIVE_TESTS") != "true" {
		t.Skip("native Linux scanner suite runs in the Docker test target")
	}
	for name, version := range toolVersions {
		out, err := exec.Command(name, scannerVersionArgs(name)...).CombinedOutput()
		if err != nil || !strings.Contains(string(out), version) {
			t.Fatalf("worker startup check failed for %s: %s %v", name, out, err)
		}
	}

	t.Setenv("WORKER_TOKEN", "fixture-worker-secret")
	var attributed atomic.Int32
	var mutationRequests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			mutationRequests.Add(1)
		}
		if r.Header.Get("X-Scanner") != "" {
			attributed.Add(1)
		}
		w.Header().Set("Server", "nginx/1.24.0")
		switch r.URL.Path {
		case "/.git/config":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "[core]\nrepositoryformatversion=0\n[remote \"origin\"]\nurl=https://fixture:credential@example.com/repo")
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "APP_ENV=testing\nDB_PASSWORD=fixture-password\nAPP_KEY=fixture-app-key\n")
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><title>Owned scanner fixture</title><a href="/api/users?token=never-store-this-value">Users</a><script src="/app.js"></script><form method="post" action="/save"><input name="email"></form></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `const github_token = "ghp_K9mVr2dPf7QsXa4Tc8NhY6Wb3JzRu5Ee0Lk1"; fetch('/api/users');`)
		case "/api/users":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"users":[]}`)
		default:
			http.NotFound(w, r)
		}
	})
	fixture := httptest.NewServer(handler)
	tlsFixture := httptest.NewTLSServer(handler)
	defer tlsFixture.Close()
	defer fixture.Close()
	s := testServer(t)
	s.state = seed(false)
	s.liveEnabled = true
	s.gatewaySecret = "fixture-egress-secret"
	target := Target{ID: "fixture-target", Domain: "fixture.example", Status: "verified", Token: "fixture-proof", Schedule: "Manual"}
	s.state.Targets = []Target{target}
	s.lookupTXT = func(context.Context, string) ([]string, error) { return []string{"fixture-proof"}, nil }
	api := httptest.NewServer(http.HandlerFunc(s.handle))
	defer api.Close()
	g := Gateway{Secret: s.gatewaySecret, API: api.URL, Token: "fixture-worker-secret", lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		if port == "443" {
			return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(tlsFixture.URL, "https://"))
		}
		if port != "80" {
			return nil, fmt.Errorf("fixture port closed")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(fixture.URL, "http://"))
	}}
	proxy := httptest.NewServer(http.HandlerFunc(g.serve))
	defer proxy.Close()
	socks, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	go func() {
		for {
			conn, err := socks.Accept()
			if err != nil {
				return
			}
			go g.socksConn(context.Background(), conn)
		}
	}()
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		for {
			packet := make([]byte, 4096)
			n, peer, err := dns.ReadFrom(packet)
			if err != nil {
				return
			}
			var message dnsmessage.Message
			if message.Unpack(packet[:n]) != nil {
				continue
			}
			message.Header.Response = true
			message.Header.RecursionAvailable = true
			message.Answers = nil
			for _, q := range message.Questions {
				if q.Type == dnsmessage.TypeA {
					message.Answers = append(message.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}}})
				}
			}
			out, err := message.Pack()
			if err == nil {
				_, _ = dns.WriteTo(out, peer)
			}
		}
	}()
	t.Setenv("EGRESS_PROXY", strings.Replace(proxy.URL, "127.0.0.1", "gateway", 1))
	t.Setenv("EGRESS_DNS", dns.LocalAddr().String())
	w := Worker{proxyLookup: func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "gateway" {
			return nil, fmt.Errorf("unexpected proxy lookup")
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}, ID: "native-fixture-worker", API: api.URL, Token: "fixture-worker-secret", Templates: "/opt/surfacer/templates", client: &http.Client{Timeout: 15 * time.Second}}
	s.state.Scans = []Scan{s.makeScan(target, "Manual")}
	var claim Claim
	if err = w.call(context.Background(), "/internal/claim", map[string]any{"worker": w.ID, "versions": toolVersions}, &claim); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	w.execute(ctx, claim)
	s.mu.Lock()
	defer s.mu.Unlock()
	scan := s.state.Scans[0]
	if scan.Status != "completed" {
		t.Logf("Blocked hosts: %v; assets: %+v", scan.Checkpoint.Blocked, scan.Checkpoint.Assets)
		for _, stage := range scan.Stages {
			t.Logf("%s: %s %s", stage.Name, stage.Status, stage.Log)
		}
		t.Fatalf("native scan did not complete: %s %s", scan.Status, scan.Error)
	}
	if len(s.state.Assets) != 1 {
		t.Fatalf("expected fixture asset, got %d", len(s.state.Assets))
	}
	if !contains(intStrings(s.state.Assets[0].Ports), "443") {
		t.Fatal("Naabu did not retain observed TLS port")
	}
	tlsFound := false
	for _, svc := range s.state.Assets[0].Services {
		if svc.Port == 443 && svc.TLSVersion != "" {
			tlsFound = true
		}
	}
	if !tlsFound {
		t.Fatal("TLSx metadata did not persist")
	}
	formFound := false
	for _, e := range s.state.Assets[0].Endpoints {
		if e.Kind == "Form" && contains(e.Parameters, "email") {
			formFound = true
		}
	}
	if !formFound {
		t.Fatal("Katana form fields were not persisted")
	}
	if len(s.state.Assets[0].Endpoints) < 2 {
		t.Fatal("Katana did not produce persistent endpoint inventory")
	}
	secretFound := false
	for _, f := range s.state.Findings {
		if strings.HasPrefix(f.Template, "gitleaks:") {
			secretFound = true
		}
		if strings.Contains(f.Evidence, "ghp_K9mVr2dPf7QsXa4Tc8NhY6Wb3JzRu5Ee0Lk1") {
			t.Fatal("public JS credential leaked into evidence")
		}
	}
	if !secretFound {
		t.Fatal("Gitleaks did not detect the public JS fixture credential")
	}
	for _, e := range s.state.Assets[0].Endpoints {
		if strings.Contains(e.URL, "never-store-this-value") {
			t.Fatal("query value persisted")
		}
	}
	if len(s.state.Findings) < 3 {
		t.Fatalf("expected real env and git findings, got %d", len(s.state.Findings))
	}
	for _, finding := range s.state.Findings {
		if strings.Contains(finding.Evidence, "fixture-password") || strings.Contains(finding.Evidence, "fixture-app-key") || strings.Contains(finding.Evidence, "fixture:credential") {
			t.Fatal("scanner evidence contains an unredacted fixture credential")
		}
	}
	if mutationRequests.Load() != 0 {
		t.Fatal("crawler submitted a form or mutated fixture")
	}
	if attributed.Load() < 2 {
		t.Fatal("scanner attribution missing")
	}
}
