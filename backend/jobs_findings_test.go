package main

import "testing"

func TestPublishScanFindingsIsAdditiveAndPreservesTriage(t *testing.T) {
	s := &Server{}
	id := fingerprint("t1", "git-config", "a.owned.example", "https://a.owned.example/.git/config")
	s.state.Findings = []Finding{
		{ID: id, TargetID: "t1", Host: "a.owned.example", Template: "git-config", MatchedAt: "https://a.owned.example/.git/config", Status: "accepted", FirstSeen: "2026-01-01T00:00:00Z", Notes: []Note{{Text: "keep"}}, EvidenceKey: "k1"},
		{ID: "other", TargetID: "t1", Host: "b.owned.example", Template: "x", Status: "open", MissingScans: 1},
	}
	sc := &Scan{TargetID: "t1", Checkpoint: Checkpoint{Findings: []Finding{
		{Host: "a.owned.example", Template: "git-config", MatchedAt: "https://a.owned.example/.git/config", Severity: "high", Title: "Git config"},
		{Host: "c.owned.example", Template: "nginx-status", MatchedAt: "https://c.owned.example/status", Severity: "low", Title: "Nginx status"},
	}}}
	found := s.publishScanFindings(sc, "2026-10-18T00:00:00Z")
	if len(found) != 2 || len(s.state.Findings) != 3 {
		t.Fatal("findings not published", found, s.state.Findings)
	}
	kept := s.state.Findings[0]
	if kept.Status != "accepted" || kept.FirstSeen != "2026-01-01T00:00:00Z" || len(kept.Notes) != 1 || kept.EvidenceKey != "k1" || kept.Title != "Git config" {
		t.Fatal("triage state lost", kept)
	}
	if s.state.Findings[1].MissingScans != 1 || s.state.Findings[1].Status != "open" {
		t.Fatal("stage publish must not run lifecycle resolution", s.state.Findings[1])
	}
	if added := s.state.Findings[2]; added.Status != "open" || added.TargetID != "t1" || added.FirstSeen != "2026-10-18T00:00:00Z" {
		t.Fatal("new finding not initialized", added)
	}
	events := len(s.state.Events)
	s.publishScanFindings(sc, "2026-10-18T00:01:00Z") // idempotent re-commit of the same checkpoint
	if len(s.state.Findings) != 3 || len(s.state.Events) != events {
		t.Fatal("re-publish duplicated findings or events", len(s.state.Findings), len(s.state.Events), events)
	}
	if s.state.Findings[2].FirstSeen != "2026-10-18T00:00:00Z" {
		t.Fatal("first-seen overwritten on re-publish")
	}
}

func TestPublishScanFindingsReopensResolved(t *testing.T) {
	s := &Server{}
	id := fingerprint("t1", "x", "a.owned.example", "https://a.owned.example/")
	s.state.Findings = []Finding{{ID: id, TargetID: "t1", Host: "a.owned.example", Template: "x", MatchedAt: "https://a.owned.example/", Status: "resolved", MissingScans: 2}}
	sc := &Scan{TargetID: "t1", Checkpoint: Checkpoint{Findings: []Finding{{Host: "a.owned.example", Template: "x", MatchedAt: "https://a.owned.example/"}}}}
	s.publishScanFindings(sc, now())
	if f := s.state.Findings[0]; f.Status != "open" || f.MissingScans != 0 {
		t.Fatal("rediscovered finding not reopened", f)
	}
}

func TestRecountAssetFindingsUsesOpenFindingsOnly(t *testing.T) {
	s := &Server{}
	s.state.Assets = []Asset{{TargetID: "t1", Host: "a.owned.example"}, {TargetID: "t2", Host: "a.owned.example", Findings: 9, Severity: "critical"}}
	s.state.Findings = []Finding{
		{Host: "a.owned.example", Status: "open", Severity: "low"},
		{Host: "a.owned.example", Status: "open", Severity: "high"},
		{Host: "a.owned.example", Status: "accepted", Severity: "critical"},
	}
	s.recountAssetFindings("t1")
	if a := s.state.Assets[0]; a.Findings != 2 || a.Severity != "high" {
		t.Fatal("asset recount incorrect", a)
	}
	if a := s.state.Assets[1]; a.Findings != 9 {
		t.Fatal("other target touched", a)
	}
}

func TestPublishScanAssetsSyncsIntermediateState(t *testing.T) {
	s := &Server{}
	sc := &Scan{
		TargetID: "t1",
		Checkpoint: Checkpoint{
			Assets: []Asset{
				{
					Host:  "api.owned.example",
					IP:    "1.2.3.4",
					Ports: []int{80, 443, 8080},
					Services: []Service{
						{Port: 8080, URL: "http://api.owned.example:8080", Status: 200, Title: "API Gateway", Technologies: []string{"Express", "Node.js"}},
					},
					Endpoints: []Endpoint{
						{URL: "http://api.owned.example:8080/v1/users", Method: "GET", Parameters: []string{"page", "limit"}, Kind: "API endpoint"},
					},
				},
			},
		},
	}
	s.publishScanAssets(sc, "2026-10-18T00:00:00Z")
	if len(s.state.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(s.state.Assets))
	}
	a := s.state.Assets[0]
	if a.Host != "api.owned.example" || a.IP != "1.2.3.4" || len(a.Ports) != 3 || len(a.Services) != 1 || len(a.Endpoints) != 1 {
		t.Fatalf("asset not synced accurately: %+v", a)
	}
	if a.Services[0].Title != "API Gateway" || len(a.Services[0].Technologies) != 2 {
		t.Fatalf("services not synced accurately: %+v", a.Services)
	}
}

func TestStageEnrichmentFindings(t *testing.T) {
	cp := Checkpoint{
		Assets: []Asset{
			{
				Host:  "app.owned.example",
				IP:    "1.2.3.5",
				Ports: []int{443, 8443},
				Services: []Service{
					{Port: 443, URL: "https://app.owned.example", Status: 200, Title: "App Portal", Technologies: []string{"React", "Nginx"}},
				},
				Endpoints: []Endpoint{
					{URL: "https://app.owned.example/search", Method: "GET", Parameters: []string{"q", "category"}, Kind: "API endpoint"},
				},
			},
		},
		Hazards: []EndpointHazard{
			{URL: "https://app.owned.example/proxy?url=REDACTED", Parameter: "url", HazardClass: "ssrf_candidate", Severity: "high"},
		},
	}

	cp = enrichHostFindings(cp, "t1")
	cp = enrichPortFindings(cp, "t1")
	cp = enrichServiceFindings(cp, "t1")
	cp = enrichEndpointFindings(cp, "t1")
	cp = enrichHazardFindings(cp, "t1")

	categories := map[string]int{}
	for _, f := range cp.Findings {
		categories[f.Category]++
	}

	if categories["host"] < 1 {
		t.Fatalf("expected host finding, got: %+v", categories)
	}
	if categories["port"] < 2 {
		t.Fatalf("expected port findings, got: %+v", categories)
	}
	if categories["endpoint"] < 1 {
		t.Fatalf("expected endpoint finding, got: %+v", categories)
	}
	if categories["hazard"] < 1 {
		t.Fatalf("expected hazard finding, got: %+v", categories)
	}

	// Verify minute fields on port finding
	var portFinding *Finding
	for i := range cp.Findings {
		if cp.Findings[i].Category == "port" && cp.Findings[i].Port == 443 {
			portFinding = &cp.Findings[i]
			break
		}
	}
	if portFinding == nil || len(portFinding.Technologies) == 0 || portFinding.StageName != "HTTP probing" {
		t.Fatalf("expected enriched port finding, got: %+v", portFinding)
	}
}

func TestScanStepFindingsLoggedAndPublished(t *testing.T) {
	s := &Server{}
	sc := &Scan{
		ID:       "scan-xyz-123",
		TargetID: "t1",
		Checkpoint: Checkpoint{
			Findings: []Finding{
				{
					Host:        "api.example.com",
					Template:    "port-443",
					Port:        443,
					Category:    "port",
					Severity:    "info",
					Title:       "Exposed HTTPS Service: 443/tcp",
					StageName:   "HTTP probing",
					Tool:        "httpx",
					StepLog:     "httpx probed 1 endpoint: HTTP 200 OK, title 'API Gateway'",
					StepSuccess: true,
				},
			},
		},
	}
	s.publishScanFindings(sc, "2026-10-18T12:00:00Z")
	if len(s.state.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(s.state.Findings))
	}
	f := s.state.Findings[0]
	if f.ScanID != "scan-xyz-123" {
		t.Errorf("expected ScanID scan-xyz-123, got %s", f.ScanID)
	}
	if f.StepLog != "httpx probed 1 endpoint: HTTP 200 OK, title 'API Gateway'" {
		t.Errorf("expected step log to be preserved, got %s", f.StepLog)
	}
	if !f.StepSuccess {
		t.Errorf("expected stepSuccess to be true")
	}
	if len(f.Notes) == 0 {
		t.Fatalf("expected audit note logging step success, got none")
	}
	if f.Notes[0].Actor != "Scanner (httpx)" {
		t.Errorf("expected actor 'Scanner (httpx)', got %s", f.Notes[0].Actor)
	}
}
