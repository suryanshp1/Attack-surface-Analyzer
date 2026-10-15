package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestVerificationUsesConfiguredDNSRelay(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("EGRESS_DNS", conn.LocalAddr().String())
	const token = "surfacer-verification=owned-test-proof"
	go func() {
		for {
			packet := make([]byte, 4096)
			n, peer, err := conn.ReadFrom(packet)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(packet[:n]) != nil {
				continue
			}
			msg.Header.Response = true
			msg.Header.RecursionAvailable = true
			for _, q := range msg.Questions {
				if q.Type == dnsmessage.TypeTXT && q.Name.String() == "_surfacer.company.com." {
					msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{token}}})
				}
			}
			data, err := msg.Pack()
			if err == nil {
				_, _ = conn.WriteTo(data, peer)
			}
		}
	}()
	s := testServer(t)
	s.state.Targets = []Target{{ID: "owned", Domain: "company.com", Status: "pending", Token: token, Schedule: "Manual"}}
	w := request(s, "POST", "/api/targets/owned/verify", `{}`)
	if w.Code != 200 || s.state.Targets[0].Status != "verified" || s.state.Targets[0].LastVerified == "" {
		t.Fatalf("relay verification failed: %d %s", w.Code, w.Body.String())
	}
	// The same resolver is used again when a scan checks ownership.
	if err := s.verifyTarget(context.Background(), &s.state.Targets[0]); err != nil {
		t.Fatal(err)
	}
}

func TestVerificationErrorsDistinguishOutageFromMissingProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		code   int
		status string
		text   string
	}{
		{"outage", &net.DNSError{Err: "timeout", IsTimeout: true}, 503, "verified", "resolver unavailable"},
		{"missing", &net.DNSError{Err: "no such host", IsNotFound: true}, 422, "paused", "No TXT record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			s.state.Targets = []Target{{ID: "owned", Domain: "company.com", Status: "verified", Token: "proof"}}
			s.lookupTXT = func(context.Context, string) ([]string, error) { return nil, tc.err }
			w := request(s, "POST", "/api/targets/owned/verify", `{}`)
			if w.Code != tc.code || s.state.Targets[0].Status != tc.status || !strings.Contains(w.Body.String(), tc.text) {
				t.Fatalf("unexpected outcome: %d %s status=%s", w.Code, w.Body.String(), s.state.Targets[0].Status)
			}
		})
	}
}
