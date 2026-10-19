package main

import (
	"context"
	"net"
	"testing"
)

func TestParseSPFRecord(t *testing.T) {
	tests := []struct {
		spf      string
		expected string
	}{
		{"v=spf1 include:_spf.google.com -all", "secure"},
		{"v=spf1 include:mail.example.com ~all", "softfail"},
		{"v=spf1 ip4:192.0.2.0/24 ?all", "permissive"},
		{"v=spf1 +all", "permissive"},
		{"v=spf1 all", "permissive"},
		{"", "missing"},
		{"invalid txt", "missing"},
	}

	for _, tc := range tests {
		got := ParseSPFRecord(tc.spf)
		if got != tc.expected {
			t.Errorf("ParseSPFRecord(%q) = %q, expected %q", tc.spf, got, tc.expected)
		}
	}
}

func TestParseDMARCRecord(t *testing.T) {
	tests := []struct {
		dmarc    string
		expected string
	}{
		{"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com", "reject"},
		{"v=DMARC1; p=quarantine; pct=100", "quarantine"},
		{"v=DMARC1; p=none; rua=mailto:reports@example.com", "none"},
		{"v=DMARC1; fo=1", "missing"},
		{"", "missing"},
		{"unrelated text", "missing"},
	}

	for _, tc := range tests {
		got := ParseDMARCRecord(tc.dmarc)
		if got != tc.expected {
			t.Errorf("ParseDMARCRecord(%q) = %q, expected %q", tc.dmarc, got, tc.expected)
		}
	}
}

func TestTakeoverFingerprintMatching(t *testing.T) {
	cases := []struct {
		cname    string
		provider string
	}{
		{"mybucket.s3.amazonaws.com", "AWS S3"},
		{"mybucket.s3-website-us-east-1.amazonaws.com", "AWS S3"},
		{"company.github.io", "GitHub Pages"},
		{"myapp.herokuapp.com", "Heroku"},
		{"myapp.herokudns.com", "Heroku"},
		{"cdn.fastly.net", "Fastly CDN"},
		{"store.myshopify.com", "Shopify"},
		{"blog.ghost.io", "Ghost"},
		{"custom.na-bootstrap1.surge.sh", "Surge"},
	}

	for _, tc := range cases {
		matched := false
		for _, fp := range TakeoverFingerprints {
			if fp.Match(tc.cname) {
				if fp.Provider != tc.provider {
					t.Errorf("For CNAME %s: got provider %s, expected %s", tc.cname, fp.Provider, tc.provider)
				}
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("For CNAME %s: expected match for provider %s, but got none", tc.cname, tc.provider)
		}
	}
}

func TestEvaluateDNSGovernanceMock(t *testing.T) {
	// A canceled fixture never queries a real DNS provider.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	posture := EvaluateDNSGovernance(ctx, &net.Resolver{}, "example.com", "scan-123")
	if posture.Domain != "example.com" || posture.ScanID != "scan-123" {
		t.Fatalf("unexpected posture: %+v", posture)
	}
}
