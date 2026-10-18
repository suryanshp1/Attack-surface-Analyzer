package main

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

type HazardRule struct {
	HazardClass string
	Severity    string
	Parameters  map[string]bool
}

var (
	ssrfParams = map[string]bool{
		"url": true, "uri": true, "dest": true, "destination": true, "target": true,
		"feed": true, "host": true, "port": true, "callback": true, "load_url": true,
		"window": true, "data": true,
	}
	redirectParams = map[string]bool{
		"redir": true, "redirect": true, "return": true, "next": true, "forward": true,
		"goto": true, "rurl": true, "return_to": true, "checkout_url": true,
	}
	lfiParams = map[string]bool{
		"file": true, "filename": true, "document": true, "folder": true, "root": true,
		"path": true, "pg": true, "style": true, "template": true, "doc": true,
		"include": true,
	}
	sqliParams = map[string]bool{
		"id": true, "select": true, "report": true, "role": true, "query": true,
		"user": true, "sort": true, "where": true, "search": true, "params": true,
		"table": true, "column": true, "filter": true,
	}
	debugParams = map[string]bool{
		"dbg": true, "debug": true, "admin": true, "adm": true, "test": true,
		"root": true, "cfg": true, "config": true, "reset": true, "shell": true,
		"toggle": true,
	}
	sensitiveExtensions = []string{
		".env", ".sql", ".bak", ".backup", ".key", ".pem", ".crt", ".config", ".ini", ".log", ".yml", ".yaml",
	}
)

var HazardRules = []HazardRule{
	{HazardClass: "ssrf_candidate", Severity: "high", Parameters: ssrfParams},
	{HazardClass: "redirect_candidate", Severity: "medium", Parameters: redirectParams},
	{HazardClass: "lfi_candidate", Severity: "high", Parameters: lfiParams},
	{HazardClass: "sqli_candidate", Severity: "high", Parameters: sqliParams},
	{HazardClass: "debug_flag", Severity: "medium", Parameters: debugParams},
}

// sanitizeURLForHazard removes raw query values and preserves parameter names
func sanitizeURLForHazard(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if len(q) > 0 {
		masked := url.Values{}
		for k := range q {
			masked.Set(k, "REDACTED")
		}
		u.RawQuery = masked.Encode()
	}
	return u.String()
}

// ClassifyEndpointHazards triages discovered endpoints into hazard categories without firing payloads.
func ClassifyEndpointHazards(endpoints []Endpoint, scanID string) []EndpointHazard {
	var hazards []EndpointHazard
	seen := map[string]bool{}

	addHazard := func(rawURL, param, hazardClass, severity string) {
		cleanURL := sanitizeURLForHazard(rawURL)
		key := cleanURL + "|" + param + "|" + hazardClass
		if seen[key] {
			return
		}
		seen[key] = true
		hazards = append(hazards, EndpointHazard{
			ID:          id(),
			ScanID:      scanID,
			URL:         cleanURL,
			Parameter:   param,
			HazardClass: hazardClass,
			Severity:    severity,
			CreatedAt:   now(),
		})
	}

	for _, ep := range endpoints {
		if ep.URL == "" {
			continue
		}
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}

		// 1. Check sensitive file extensions
		ext := strings.ToLower(path.Ext(u.Path))
		base := strings.ToLower(path.Base(u.Path))
		for _, sExt := range sensitiveExtensions {
			if ext == sExt || base == sExt || strings.HasSuffix(base, sExt) {
				addHazard(ep.URL, sExt, "sensitive_file", "high")
				break
			}
		}

		// 2. Check query parameter hazards
		q := u.Query()
		var paramKeys []string
		for k := range q {
			paramKeys = append(paramKeys, strings.ToLower(strings.TrimSpace(k)))
		}
		for _, p := range ep.Parameters {
			paramKeys = append(paramKeys, strings.ToLower(strings.TrimSpace(p)))
		}
		paramKeys = dedupeStrings(paramKeys)

		for _, param := range paramKeys {
			for _, rule := range HazardRules {
				if rule.Parameters[param] {
					addHazard(ep.URL, param, rule.HazardClass, rule.Severity)
				}
			}
		}
	}

	sort.Slice(hazards, func(i, j int) bool {
		if hazards[i].Severity != hazards[j].Severity {
			rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
			return rank[hazards[i].Severity] < rank[hazards[j].Severity]
		}
		return hazards[i].URL < hazards[j].URL
	})

	return hazards
}
