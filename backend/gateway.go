package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var blockedRanges = []string{"168.63.129.16/32", "fec0::/10", "192.88.99.0/24", "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32", "2001::/32", "2002::/16", "64:ff9b::/96"}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range blockedRanges {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

type Gateway struct {
	tunnelMu    sync.Mutex
	tunnelSlots map[string]chan struct{}
	traffic     trafficGovernor
	tcpTraffic  trafficGovernor
	Secret      string
	API         string
	Token       string
	lookup      func(context.Context, string) ([]netip.Addr, error)
	dial        func(context.Context, string, string) (net.Conn, error)
	authorize   func(context.Context, string) bool
}

func (g *Gateway) safeDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if !webPort(port) {
		return nil, errors.New("only HTTP and HTTPS are allowed")
	}
	return g.resolveDial(ctx, host, port)
}
func (g *Gateway) resolveDial(ctx context.Context, host, port string) (net.Conn, error) {
	var ips []netip.Addr
	var err error
	if literal, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{literal}
	} else if g.lookup != nil {
		ips, err = g.lookup(ctx, host)
	} else {
		ips, err = pinnedResolver().LookupNetIP(ctx, "ip", host)
	}
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("host has no public addresses")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, fmt.Errorf("blocked non-public destination %s", ip)
		}
	}
	dial := g.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	for _, ip := range ips {
		conn, e := dial(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		err = e
	}
	return nil, err
}
func (g *Gateway) active(ctx context.Context, permit string) bool {
	if g.authorize != nil {
		return g.authorize(ctx, permit)
	}
	payload, _ := json.Marshal(map[string]string{"worker": "egress-gateway", "permit": permit})
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, "POST", g.API+"/internal/authorize", strings.NewReader(string(payload)))
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode == 200
}
func (g *Gateway) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" && r.Method == "GET" && !r.URL.IsAbs() {
		respond(w, 200, map[string]string{"status": "ok"})
		return
	}
	auth := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		http.Error(w, "Scan authorization required", 407)
		return
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		http.Error(w, "Scan authorization required", 407)
		return
	}
	permit, err := checkPermit(parts[1], g.Secret)
	if err != nil || !g.active(r.Context(), parts[1]) {
		http.Error(w, "Scan permit is invalid, expired or canceled", 403)
		return
	}
	if r.URL.Path == "/internal/cooldown" && !r.URL.IsAbs() && r.Method == "POST" {
		var p struct {
			Host       string `json:"host"`
			Status     int    `json:"status"`
			RetryAfter string `json:"retryAfter"`
		}
		if !decode(w, r, &p) {
			return
		}
		if !inScope(p.Host, permit.Root) || (p.Status != 403 && p.Status != 429 && p.Status != 503) {
			http.Error(w, "Invalid cooldown report", 400)
			return
		}
		g.traffic.observe(permit.Root, p.Status, p.RetryAfter)
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	host := r.URL.Hostname()
	port := r.URL.Port()
	if r.Method == "CONNECT" {
		host, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			http.Error(w, "Invalid CONNECT destination", 400)
			return
		}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	providers := map[string]bool{"crt.sh": true, "api.hackertarget.com": true, "rapiddns.io": true, "web.archive.org": true, "index.commoncrawl.org": true, "data.commoncrawl.org": true}
	if !inScope(host, permit.Root) && !providers[host] {
		GlobalTelemetry.RecordBlockedEgress()
		Log(r.Context()).Warn("gateway_blocked_destination", "host", host, "reason", "out_of_scope")
		http.Error(w, "Destination outside verified scope", 403)
		return
	}
	if port == "" {
		port = "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
	}
	if !webPort(port) {
		http.Error(w, "Port outside HTTP scope", 403)
		return
	}
	key := permit.Root
	if providers[host] {
		key = host
	}
	if r.Method == "CONNECT" {
		releaseTunnel, err := g.reserveTunnel(r.Context(), key)
		if err != nil {
			http.Error(w, "Tunnel admission canceled or unavailable", 503)
			return
		}
		defer releaseTunnel()
	}
	release, err := g.traffic.acquire(r.Context(), key)
	if err != nil {
		http.Error(w, "Traffic wait canceled", 503)
		return
	}
	defer release()
	// A queued request must still have a live scan lease when it is admitted.
	if !g.active(r.Context(), parts[1]) {
		http.Error(w, "Scan canceled while waiting", 403)
		return
	}
	if r.Method == "CONNECT" {
		upstream, err := g.safeDial(r.Context(), "tcp", net.JoinHostPort(host, port))
		if err != nil {
			GlobalTelemetry.RecordBlockedEgress()
			Log(r.Context()).Warn("gateway_blocked_dial", "host", host, "port", port, "err", err.Error())
			http.Error(w, "Destination blocked or unavailable", 502)
			return
		}
		GlobalTelemetry.RecordEgress()
		h, ok := w.(http.Hijacker)
		if !ok {
			upstream.Close()
			http.Error(w, "CONNECT unsupported", 500)
			return
		}
		client, buffer, err := h.Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		defer client.Close()
		defer upstream.Close()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		release() // pacing applies to tunnel admission; tunnel capacity is held separately
		deadline := time.Now().Add(2 * time.Minute)
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
		done := make(chan struct{})
		go func() { defer close(done); _, _ = io.Copy(upstream, buffer); _ = upstream.Close() }()
		watch := make(chan struct{})
		defer close(watch)
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-watch:
					return
				case <-ticker.C:
					if !g.active(context.Background(), parts[1]) {
						client.Close()
						upstream.Close()
						return
					}
				}
			}
		}()
		_, _ = io.Copy(client, upstream)
		return
	}
	if r.URL.Scheme != "http" || !r.URL.IsAbs() {
		http.Error(w, "HTTP proxy request required", 400)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	out.Header.Set("X-Scanner", "Surfacer/"+permit.Scan)
	out.Header.Set("User-Agent", scannerAgent(permit.Scan, r.Method+":"+r.URL.Path))
	transport := &http.Transport{DialContext: g.safeDial, ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	res, err := transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "Destination blocked or unavailable", 502)
		return
	}
	defer res.Body.Close()
	g.traffic.observe(key, res.StatusCode, res.Header.Get("Retry-After"))
	for k, v := range res.Header {
		for _, value := range v {
			w.Header().Add(k, value)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(res.Body, 2<<20))
}
func runGateway() {
	secret := os.Getenv("EGRESS_SECRET")
	token := os.Getenv("WORKER_TOKEN")
	if secret == "" || token == "" {
		log.Fatal("Gateway requires EGRESS_SECRET and WORKER_TOKEN")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	g := Gateway{Secret: secret, Token: token, API: os.Getenv("WORKER_API_URL")}
	if g.API == "" {
		g.API = "http://api:8080"
	}
	dnsAddr := os.Getenv("DNS_LISTEN_ADDR")
	if dnsAddr == "" {
		dnsAddr = "0.0.0.0:5353"
	}
	go dnsRelay(ctx, dnsAddr)
	go g.socksServer(ctx, "0.0.0.0:1080")
	srv := &http.Server{Addr: ":3128", Handler: http.HandlerFunc(g.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = srv.Shutdown(c)
	}()
	log.Print("Scope-checking egress gateway listening on :3128")
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
func dnsRelay(ctx context.Context, address string) {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	semaphore := make(chan struct{}, 30)
	for {
		buf := make([]byte, 4096)
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var parser dnsmessage.Parser
		_, err = parser.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := parser.Question()
		if err != nil || q.Class != dnsmessage.ClassINET || q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA && q.Type != dnsmessage.TypeTXT && q.Type != dnsmessage.TypeCNAME {
			continue
		}
		select {
		case semaphore <- struct{}{}:
		default:
			continue
		}
		go func(packet []byte, peer net.Addr) {
			defer func() { <-semaphore }()
			up, e := net.DialTimeout("udp", "1.1.1.1:53", 3*time.Second)
			if e != nil {
				return
			}
			defer up.Close()
			up.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e = up.Write(packet); e != nil {
				return
			}
			answer := make([]byte, 4096)
			size, e := up.Read(answer)
			if e == nil {
				_, _ = conn.WriteTo(answer[:size], peer)
			}
		}(append([]byte{}, buf[:n]...), peer)
	}
}

func (g *Gateway) reserveTunnel(ctx context.Context, root string) (func(), error) {
	g.tunnelMu.Lock()
	if g.tunnelSlots == nil {
		g.tunnelSlots = map[string]chan struct{}{}
	}
	slots := g.tunnelSlots[root]
	if slots == nil {
		if len(g.tunnelSlots) >= 4096 {
			g.tunnelMu.Unlock()
			return nil, errors.New("tunnel scope capacity reached")
		}
		slots = make(chan struct{}, 10)
		g.tunnelSlots[root] = slots
	}
	g.tunnelMu.Unlock()
	select {
	case slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-slots }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
