package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestScannerResolvesProxyWithDockerDNSFirst(t *testing.T) {
	called := false
	proxy, err := scannerProxy(context.Background(), "http://gateway:3128", func(ctx context.Context, host string) ([]net.IPAddr, error) {
		called = true
		if host != "gateway" {
			t.Fatal("target sent to Docker lookup")
		}
		return []net.IPAddr{{IP: net.ParseIP("172.30.88.3")}}, nil
	})
	if err != nil || !called || proxy.String() != "http://172.30.88.3:3128" {
		t.Fatalf("Docker proxy sent to public scanner DNS: %v %v", proxy, err)
	}
	called = false
	_, err = scannerProxy(context.Background(), "http://127.0.0.1:3128", func(context.Context, string) ([]net.IPAddr, error) {
		called = true
		return nil, errors.New("unexpected lookup")
	})
	if err != nil || called {
		t.Fatal("literal proxy requires DNS")
	}
}
func TestPrivateHostsAreExclusionsNotCoverageFailures(t *testing.T) {
	cp := Checkpoint{DNS: map[string][]string{"private.owned.example": {"10.0.0.1"}, "public.owned.example": {"1.1.1.1"}}, Blocked: []string{"private.owned.example", "private.owned.example"}}
	if len(coverageBlockers(cp)) != 0 || len(excludedHosts(cp)) != 1 {
		t.Fatal("expected scope exclusions make public coverage fail")
	}
	cp.Blocked = append(cp.Blocked, "public.owned.example", "public.owned.example")
	if len(coverageBlockers(cp)) != 1 {
		t.Fatal("public coverage error lost or duplicated")
	}
	cp.PortIncomplete = []string{"public.owned.example"}
	message := coverageSummary(cp)
	if !strings.Contains(message, "Port checks remain incomplete for 1 hosts") || !strings.Contains(message, "1 non-public hosts") {
		t.Fatal(message)
	}
}
func TestCompleteScanWithPrivateExclusionRetainsUncheckedFindings(t *testing.T) {
	t.Setenv("WORKER_TOKEN", "fixture-worker")
	s := testServer(t)
	s.state = emptyState()
	s.allowUnverified = true
	s.liveEnabled = true
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
	s.state.Findings = []Finding{{ID: "prior", TargetID: "target", Host: "private.owned.example", Template: "git-config", Status: "open"}}
	s.state.Scans = []Scan{{ID: "scan", TargetID: "target", Domain: "owned.example", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Stages: []Stage{{Name: "Detection", Status: "completed"}}, Checkpoint: Checkpoint{DNS: map[string][]string{"private.owned.example": {"10.0.0.1"}}, Blocked: []string{"private.owned.example"}}}}
	r := httptest.NewRequest("POST", "/internal/complete", strings.NewReader(`{"worker":"fixture","scanId":"scan","lease":"lease"}`))
	r.Header.Set("Authorization", "Bearer fixture-worker")
	response := httptest.NewRecorder()
	s.handle(response, r)
	if response.Code != 200 || s.state.Scans[0].Status != "completed" {
		t.Fatal(response.Code, response.Body.String(), s.state.Scans[0].Error)
	}
	if s.state.Findings[0].MissingScans != 0 || s.state.Findings[0].Status != "open" {
		t.Fatal("excluded findings were resolved without coverage")
	}
}
func TestHistoricalPartialWarningExplainsActualGap(t *testing.T) {
	s := testServer(t)
	s.state.Scans = []Scan{{Status: "partial", Error: "Some hosts were blocked or did not complete detection; lifecycle resolution is disabled for this scan.", Checkpoint: Checkpoint{PortIncomplete: []string{"public.owned.example"}, DNS: map[string][]string{"private.owned.example": {"10.0.0.1"}}, Blocked: []string{"private.owned.example"}}}}
	public := s.publicState()
	if !strings.Contains(public.Scans[0].Error, "Port checks remain incomplete") || len(public.Scans[0].ExcludedHosts) != 1 {
		t.Fatal("historical generic warning not explained")
	}
}

func TestExcludedHostEndpointsAreRetained(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	s.state.Assets = []Asset{{ID: fingerprint("target", "private.owned.example"), TargetID: "target", Host: "private.owned.example", URL: "https://private.owned.example", Endpoints: []Endpoint{{ID: "endpoint", URL: "https://private.owned.example/api", Method: "GET"}}}}
	scan := Scan{TargetID: "target", Stages: []Stage{{Name: "Endpoint crawling", Status: "completed"}}, Checkpoint: Checkpoint{DNS: map[string][]string{"private.owned.example": {"10.0.0.1"}}, Assets: []Asset{{Host: "private.owned.example", Blocked: true}}}}
	s.normalize(&scan, true)
	s.normalize(&scan, true)
	endpoints := s.state.Assets[0].Endpoints
	if len(endpoints) != 1 || endpoints[0].Removed || endpoints[0].MissingScans != 0 {
		t.Fatal("policy exclusion falsely removed previously observed endpoints")
	}
}

func TestPersistentTunnelsDoNotStarveHTTP(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("fixture")) }))
	defer fixture.Close()
	g := Gateway{Secret: "fixture-secret", authorize: func(context.Context, string) bool { return true }, lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		if port == "80" {
			return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(fixture.URL, "http://"))
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(fixture.URL, "http://"))
	}}
	g.traffic.interval = time.Millisecond
	proxy := httptest.NewServer(http.HandlerFunc(g.serve))
	defer proxy.Close()
	permit := signPermit(Permit{Scan: "fixture", Root: "owned.example", Lease: "lease", Expires: time.Now().Add(time.Minute).Unix()}, g.Secret)
	address := strings.TrimPrefix(proxy.URL, "http://")
	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "CONNECT owned.example:443 HTTP/1.1\r\nHost: owned.example:443\r\nProxy-Authorization: Basic %s\r\n\r\n", base64.StdEncoding.EncodeToString([]byte("scan:"+permit)))
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
		if err != nil || response.StatusCode != 200 {
			t.Fatalf("fixture tunnel failed: %v", err)
		}
	}
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("scan", permit)
	transport := &http.Transport{Proxy: http.ProxyURL(u)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://owned.example/")
	if err != nil {
		t.Fatalf("persistent HTTPS tunnels starved HTTP: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
}

func TestHTTPDeadlineRetainsRealServiceResponses(t *testing.T) {
	cp := Checkpoint{Assets: []Asset{{Host: "good.owned.example", Ports: []int{443}}, {Host: "unfinished.owned.example", Ports: []int{443}}}}
	worker := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		return []byte("{\"url\":\"https://good.owned.example:443\",\"status_code\":200}\n"), "", context.DeadlineExceeded
	}}
	result, log, err := worker.probe(context.Background(), Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 5, Concurrency: 2}}, cp, "http://127.0.0.1:3128", t.TempDir())
	if err != nil || result.Assets[0].URL == "" || len(result.Assets[0].Services) != 1 || !contains(result.Blocked, "unfinished.owned.example") || !strings.Contains(log, "retained 1 completed probe records") {
		t.Fatalf("HTTP deadline lost results or claimed clean coverage: %s %v", log, err)
	}
}
