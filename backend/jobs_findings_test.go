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
