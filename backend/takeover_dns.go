package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

type TakeoverFingerprint struct {
	Provider string
	Match    func(cname string) bool
}

var TakeoverFingerprints = []TakeoverFingerprint{
	{
		Provider: "AWS S3",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, ".s3.amazonaws.com") ||
				strings.Contains(cname, ".s3-website-") ||
				strings.Contains(cname, ".s3-website.") ||
				regexp.MustCompile(`\.s3[-.][a-z0-9-]+\.amazonaws\.com$`).MatchString(cname)
		},
	},
	{
		Provider: "GitHub Pages",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, ".github.io")
		},
	},
	{
		Provider: "Heroku",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, ".herokudns.com") || strings.HasSuffix(cname, ".herokuapp.com")
		},
	},
	{
		Provider: "Fastly CDN",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, ".fastly.net")
		},
	},
	{
		Provider: "Shopify",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, "myshopify.com")
		},
	},
	{
		Provider: "Ghost",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, ".ghost.io")
		},
	},
	{
		Provider: "Surge",
		Match: func(cname string) bool {
			return strings.HasSuffix(cname, "na-bootstrap1.surge.sh") || strings.HasSuffix(cname, ".surge.sh")
		},
	},
}

// EvaluateSubdomainTakeover checks if a host has a CNAME matching a cloud service fingerprint
// whose target does not resolve (NXDOMAIN / orphaned), indicating a dangling CNAME takeover candidate.
func EvaluateSubdomainTakeover(ctx context.Context, resolver *net.Resolver, host, rootDomain, scanID string) (*SubdomainTakeover, error) {
	cname, err := resolver.LookupCNAME(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	cleanCNAME := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	cleanHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if cleanCNAME == "" || cleanCNAME == cleanHost {
		return nil, nil
	}

	var matchedProvider string
	for _, fp := range TakeoverFingerprints {
		if fp.Match(cleanCNAME) {
			matchedProvider = fp.Provider
			break
		}
	}
	if matchedProvider == "" {
		return nil, nil
	}

	// Verify if the terminal CNAME resolves to any active IP address
	ips, err := resolver.LookupNetIP(ctx, "ip", cleanCNAME)
	isOrphaned := false
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			isOrphaned = true
		} else {
			return nil, err
		}
	} else if len(ips) == 0 {
		isOrphaned = true
	}

	if isOrphaned {
		return &SubdomainTakeover{
			ID:              id(),
			ScanID:          scanID,
			Subdomain:       cleanHost,
			CNAME:           cleanCNAME,
			ServiceProvider: matchedProvider,
			Status:          "open",
			FirstSeen:       now(),
			LastSeen:        now(),
			ReopenCount:     0,
		}, nil
	}
	return nil, nil
}

// ParseSPFRecord extracts qualifier policy from SPF TXT record:
// -all -> secure
// ~all -> softfail
// +all / ?all -> permissive
func ParseSPFRecord(spf string) string {
	spf = strings.TrimSpace(spf)
	if spf == "" {
		return "missing"
	}
	lower := strings.ToLower(spf)
	if !strings.HasPrefix(lower, "v=spf1") {
		return "missing"
	}
	parts := strings.Fields(lower)
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		switch part {
		case "-all":
			return "secure"
		case "~all":
			return "softfail"
		case "+all", "?all", "all":
			return "permissive"
		}
	}
	return "permissive"
}

// ParseDMARCRecord extracts policy from DMARC TXT record:
// p=reject -> reject
// p=quarantine -> quarantine
// p=none -> none
func ParseDMARCRecord(dmarc string) string {
	dmarc = strings.TrimSpace(dmarc)
	if dmarc == "" {
		return "missing"
	}
	lower := strings.ToLower(dmarc)
	if !strings.HasPrefix(lower, "v=dmarc1") {
		return "missing"
	}
	re := regexp.MustCompile(`\bp=([a-z]+)`)
	m := re.FindStringSubmatch(lower)
	if len(m) > 1 {
		switch m[1] {
		case "reject":
			return "reject"
		case "quarantine":
			return "quarantine"
		case "none":
			return "none"
		}
	}
	return "missing"
}

// EvaluateDNSGovernance audits SPF, DMARC, DKIM, and MX posture for the root domain.
func EvaluateDNSGovernance(ctx context.Context, resolver *net.Resolver, domain, scanID string) DomainDNSPosture {
	cleanDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	posture := DomainDNSPosture{
		ID:          id(),
		ScanID:      scanID,
		Domain:      cleanDomain,
		SPFStatus:   "missing",
		DMARCPolicy: "missing",
		MXRecords:   []MXRecord{},
		CreatedAt:   now(),
	}

	// 1. Audit SPF
	if txts, err := resolver.LookupTXT(ctx, cleanDomain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
				posture.SPFRecord = txt
				posture.SPFStatus = ParseSPFRecord(txt)
				break
			}
		}
	}

	// 2. Audit DMARC
	if dmarcTxts, err := resolver.LookupTXT(ctx, "_dmarc."+cleanDomain); err == nil {
		for _, txt := range dmarcTxts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
				posture.DMARCRecord = txt
				posture.DMARCPolicy = ParseDMARCRecord(txt)
				break
			}
		}
	}

	// 3. Audit DKIM with common enterprise selectors
	dkimSelectors := []string{"google._domainkey", "default._domainkey", "k1._domainkey"}
	for _, selector := range dkimSelectors {
		selQuery := selector + "." + cleanDomain
		if selTxts, err := resolver.LookupTXT(ctx, selQuery); err == nil && len(selTxts) > 0 {
			for _, txt := range selTxts {
				lower := strings.ToLower(txt)
				if strings.Contains(lower, "v=dkim1") || strings.Contains(lower, "k=rsa") || strings.Contains(lower, "p=") {
					posture.DKIMDetected = true
					break
				}
			}
		}
		if posture.DKIMDetected {
			break
		}
	}

	// 4. Audit MX Records
	if mxList, err := resolver.LookupMX(ctx, cleanDomain); err == nil {
		for _, mx := range mxList {
			mxHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mx.Host), "."))
			rec := MXRecord{
				Host: mxHost,
				Pref: int(mx.Pref),
				IPs:  []string{},
			}
			if ips, ipErr := resolver.LookupNetIP(ctx, "ip", mxHost); ipErr == nil {
				for _, ip := range ips {
					rec.IPs = append(rec.IPs, ip.String())
				}
			}
			posture.MXRecords = append(posture.MXRecords, rec)
		}
	}

	return posture
}

func makeSafeGatewayResolver(dnsAddr string) *net.Resolver {
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", dnsAddr)
		},
	}
}

// Ensure publicIP is respected when inspecting records
func isRecordPublic(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	return publicIP(addr)
}
