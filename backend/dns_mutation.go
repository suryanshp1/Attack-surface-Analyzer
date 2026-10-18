package main

import (
	"sort"
	"strings"
)

// Standard enterprise keywords, prefixes, and suffixes (strictly <= 150 items)
var EnterpriseDNSKeywords = []string{
	"dev", "devel", "development", "stage", "staging", "uat", "qa", "test", "testing", "demo",
	"sandbox", "preview", "pre", "canary", "beta", "alpha", "pilot", "lab", "temp", "local",
	"prod", "production", "live", "release", "corp", "internal", "intranet", "private", "dmz",
	"admin", "administrator", "adm", "manage", "management", "portal", "control", "dashboard",
	"api", "api-dev", "api-stage", "api-test", "api-v1", "api-v2", "apis", "gateway", "gw",
	"auth", "login", "signin", "sso", "idp", "identity", "oauth", "saml", "cas", "ldap",
	"vpn", "remote", "bastion", "connect", "access", "secure", "proxy", "waf", "edge",
	"mail", "webmail", "smtp", "pop", "imap", "mx", "email", "relay", "exchange",
	"app", "apps", "web", "www", "m", "mobile", "frontend", "backend", "core", "hub",
	"status", "health", "ping", "monitor", "monitoring", "metrics", "grafana", "prometheus",
	"logs", "logging", "elastic", "kibana", "siem", "splunk", "trace", "telemetry",
	"ci", "cd", "build", "jenkins", "gitlab", "git", "github", "registry", "docker", "k8s",
	"backup", "bak", "archive", "storage", "files", "share", "s3", "blob", "ftp", "sftp",
	"db", "database", "sql", "postgres", "mysql", "redis", "cache", "search", "solr", "data",
	"billing", "pay", "payment", "checkout", "shop", "store", "commerce", "cart",
	"help", "support", "docs", "documentation", "kb", "wiki", "faq", "service", "ticket",
	"cdn", "static", "assets", "media", "images", "img", "res", "download",
}

// GenerateDNSMutations generates deterministic candidate subdomains bounded to <= 1000 items.
func GenerateDNSMutations(subdomains []string, rootDomain string, maxCandidates int) []string {
	if maxCandidates <= 0 || maxCandidates > 1000 {
		maxCandidates = 1000
	}
	rootDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rootDomain), "."))
	if rootDomain == "" {
		return nil
	}

	known := map[string]bool{rootDomain: true}
	var existingLabels []string

	for _, s := range subdomains {
		h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if !inScope(h, rootDomain) || !domainPattern.MatchString(h) {
			continue
		}
		known[h] = true
		if h != rootDomain {
			prefix := strings.TrimSuffix(strings.TrimSuffix(h, "."+rootDomain), rootDomain)
			parts := strings.Split(prefix, ".")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if len(p) > 1 && len(p) < 30 {
					existingLabels = append(existingLabels, p)
				}
			}
		}
	}

	existingLabels = dedupeStrings(existingLabels)
	candidatesMap := map[string]bool{}

	addCandidate := func(cand string) {
		cand = strings.ToLower(strings.TrimSpace(cand))
		if len(candidatesMap) >= maxCandidates {
			return
		}
		if !known[cand] && inScope(cand, rootDomain) && domainPattern.MatchString(cand) {
			candidatesMap[cand] = true
		}
	}

	// 1. Standalone enterprise keywords as direct subdomains: e.g. dev.example.com, vpn.example.com
	for _, kw := range EnterpriseDNSKeywords {
		addCandidate(kw + "." + rootDomain)
		if len(candidatesMap) >= maxCandidates {
			break
		}
	}

	// 2. Prefix mutations on existing labels: e.g. dev-api.example.com, stage-portal.example.com
	for _, label := range existingLabels {
		for _, kw := range EnterpriseDNSKeywords {
			addCandidate(kw + "-" + label + "." + rootDomain)
			addCandidate(label + "-" + kw + "." + rootDomain)
			if len(candidatesMap) >= maxCandidates {
				break
			}
		}
		if len(candidatesMap) >= maxCandidates {
			break
		}
	}

	// 3. Two-level mutations if budget allows: e.g. dev.api.example.com
	for _, label := range existingLabels {
		for _, kw := range EnterpriseDNSKeywords[:20] {
			addCandidate(kw + "." + label + "." + rootDomain)
			if len(candidatesMap) >= maxCandidates {
				break
			}
		}
		if len(candidatesMap) >= maxCandidates {
			break
		}
	}

	var results []string
	for c := range candidatesMap {
		results = append(results, c)
	}
	sort.Strings(results)
	if len(results) > maxCandidates {
		results = results[:maxCandidates]
	}
	return results
}
