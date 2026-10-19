package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSRelayAllowsMXAndFiltersDisallowed(t *testing.T) {
	// Upstream mock DNS server responding to MX queries
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := upstreamConn.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}
			msg.Header.Response = true
			for _, q := range msg.Questions {
				if q.Type == dnsmessage.TypeMX {
					mxName, _ := dnsmessage.NewName("mail.example.com.")
					msg.Answers = append(msg.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Name,
							Type:  dnsmessage.TypeMX,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.MXResource{
							Pref: 10,
							MX:   mxName,
						},
					})
				}
			}
			packed, err := msg.Pack()
			if err == nil {
				_, _ = upstreamConn.WriteTo(packed, peer)
			}
		}
	}()

	t.Setenv("EGRESS_DNS", upstreamConn.LocalAddr().String())

	// Start dnsRelay on a random port
	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := relayConn.LocalAddr().String()
	relayConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go dnsRelay(ctx, relayAddr)
	time.Sleep(50 * time.Millisecond)

	// Send an MX query to relay
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", relayAddr)
		},
	}

	mxList, err := resolver.LookupMX(ctx, "example.com")
	if err != nil {
		t.Fatalf("expected MX query through relay to succeed, got: %v", err)
	}
	if len(mxList) != 1 || mxList[0].Host != "mail.example.com." || mxList[0].Pref != 10 {
		t.Fatalf("unexpected MX response: %+v", mxList)
	}
}
