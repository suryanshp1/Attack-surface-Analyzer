package main

import (
	"testing"
)

func TestClassifyEndpointHazards(t *testing.T) {
	endpoints := []Endpoint{
		{
			URL:        "https://api.example.com/fetch?url=https://internal.service/data",
			Parameters: []string{"url"},
		},
		{
			URL:        "https://auth.example.com/login?redirect=/dashboard",
			Parameters: []string{"redirect"},
		},
		{
			URL:        "https://docs.example.com/view?file=report.pdf",
			Parameters: []string{"file"},
		},
		{
			URL:        "https://store.example.com/item?id=123&query=search_term",
			Parameters: []string{"id", "query"},
		},
		{
			URL:        "https://admin.example.com/test?debug=true",
			Parameters: []string{"debug"},
		},
		{
			URL: "https://example.com/backup/database.sql",
		},
		{
			URL: "https://example.com/.env",
		},
		{
			URL: "https://example.com/about",
		},
	}

	hazards := ClassifyEndpointHazards(endpoints, "scan-1")
	if len(hazards) < 7 {
		t.Fatalf("expected at least 7 hazards classified, got %d", len(hazards))
	}

	classes := map[string]bool{}
	for _, h := range hazards {
		classes[h.HazardClass] = true
	}

	requiredClasses := []string{
		"ssrf_candidate",
		"redirect_candidate",
		"lfi_candidate",
		"sqli_candidate",
		"debug_flag",
		"sensitive_file",
	}

	for _, req := range requiredClasses {
		if !classes[req] {
			t.Errorf("expected hazard class %s to be present, but was missing", req)
		}
	}
}
