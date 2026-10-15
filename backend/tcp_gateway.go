package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var commonPorts = []int{21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 5900, 6379, 6443, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 9443, 11211, 27017}

func webPort(port string) bool {
	return contains([]string{"80", "443", "3000", "8000", "8080", "8443", "8888", "9000", "9090", "9200", "9443"}, port)
}
func scanPort(port int) bool {
	for _, p := range commonPorts {
		if p == port {
			return true
		}
	}
	return false
}
func (g *Gateway) tcpActive(ctx context.Context, scan, lease, destination string, port int) (string, bool) {
	payload, _ := json.Marshal(map[string]any{"worker": "egress-gateway", "scanId": scan, "lease": lease, "destination": destination, "port": port})
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, "POST", g.API+"/internal/tcp-authorize", strings.NewReader(string(payload)))
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	var result struct {
		Root string `json:"root"`
	}
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&result) != nil {
		return "", false
	}
	return result.Root, true
}
func (s *Server) tcpAuthorized(scan, lease, host string, port int) (string, bool) {
	if s.state.Settings.Paused || !scanPort(port) {
		return "", false
	}
	for _, sc := range s.state.Scans {
		until, _ := time.Parse(time.RFC3339, sc.LeaseUntil)
		if sc.ID != scan || sc.Lease == "" || sc.Lease != lease || sc.Status != "running" || time.Now().After(until) {
			continue
		}
		for _, t := range s.state.Targets {
			if t.ID != sc.TargetID || !s.targetCanScan(&t) {
				continue
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				if !publicIP(ip) {
					return "", false
				}
				for name, ips := range sc.Checkpoint.DNS {
					if inScope(name, t.Domain) && contains(ips, host) {
						return t.Domain, true
					}
				}
			} else if inScope(host, t.Domain) {
				return t.Domain, true
			}
		}
	}
	return "", false
}
func (g *Gateway) socksServer(ctx context.Context, address string) {
	g.tcpTraffic.interval = 100 * time.Millisecond
	g.tcpTraffic.concurrency = 5
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, 64)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); g.socksConn(ctx, conn) }()
		default:
			conn.Close()
		}
	}
}
func (g *Gateway) socksConn(ctx context.Context, client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(15 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	auth := false
	for _, m := range methods {
		if m == 2 {
			auth = true
		}
	}
	if !auth {
		client.Write([]byte{5, 255})
		return
	}
	client.Write([]byte{5, 2})
	if _, err := io.ReadFull(client, head); err != nil || head[0] != 1 {
		return
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(client, user); err != nil {
		return
	}
	length := []byte{0}
	if _, err := io.ReadFull(client, length); err != nil {
		return
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(client, password); err != nil {
		return
	}
	scan, lease := string(user), string(password)
	if len(scan) != 32 || len(lease) != 32 {
		client.Write([]byte{1, 1})
		return
	}
	client.Write([]byte{1, 0})
	request := make([]byte, 4)
	if _, err := io.ReadFull(client, request); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	var host string
	switch request[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		if _, err := io.ReadFull(client, length); err != nil {
			return
		}
		b := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = strings.ToLower(string(b))
	default:
		return
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(client, b); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(b))
	root, ok := g.tcpActive(ctx, scan, lease, host, port)
	if !ok {
		client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	release, err := g.tcpTraffic.acquire(ctx, root)
	if err != nil {
		return
	}
	defer release()
	if _, ok = g.tcpActive(ctx, scan, lease, host, port); !ok {
		return
	}
	dialCtx, stopDial := context.WithTimeout(ctx, time.Second)
	upstream, err := g.resolveDial(dialCtx, host, strconv.Itoa(port))
	stopDial()
	if err != nil {
		client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	client.SetDeadline(time.Now().Add(45 * time.Second))
	upstream.SetDeadline(time.Now().Add(45 * time.Second))
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				client.Close()
				upstream.Close()
				return
			case <-done:
				return
			case <-ticker.C:
				if _, ok := g.tcpActive(ctx, scan, lease, host, port); !ok {
					client.Close()
					upstream.Close()
					return
				}
			}
		}
	}()
	go func() { io.Copy(upstream, client); upstream.Close() }()
	io.Copy(client, upstream)
}
func socksProxy(c Claim) string {
	u, err := urlParseProxy(c.Proxy)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("socks5://%s:%s@%s:1080", c.Scan.ID, c.Scan.Lease, u)
}
func urlParseProxy(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}
