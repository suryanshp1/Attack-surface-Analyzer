package main

import (
	"strings"
	"testing"
)

func TestGenerateDNSMutations(t *testing.T) {
	root := "company.com"
	subdomains := []string{"api.company.com", "portal.company.com", "other.example.com"}

	mutations := GenerateDNSMutations(subdomains, root, 100)
	if len(mutations) == 0 {
		t.Fatal("expected mutations, got none")
	}
	if len(mutations) > 100 {
		t.Fatalf("expected <= 100 mutations, got %d", len(mutations))
	}

	for _, m := range mutations {
		if !strings.HasSuffix(m, ".company.com") {
			t.Fatalf("mutation %s escaped root scope %s", m, root)
		}
		if m == "api.company.com" || m == "portal.company.com" {
			t.Fatalf("mutation %s included existing known subdomain", m)
		}
	}
}

func TestGenerateDNSMutationsBounds(t *testing.T) {
	root := "example.com"
	subdomains := []string{"a.example.com", "b.example.com"}

	mutations := GenerateDNSMutations(subdomains, root, 5000)
	if len(mutations) > 1000 {
		t.Fatalf("mutations exceeded hard 1000 limit: %d", len(mutations))
	}
}
