package main

import "strings"

func emptyState() State {
	return State{Targets: []Target{}, Assets: []Asset{}, Findings: []Finding{}, Scans: []Scan{}, Events: []Event{}, Audit: []Event{}, Settings: Settings{Name: "My workspace", Rate: 20, Concurrency: 5, Retention: 90}}
}

// Remove records explicitly marked as legacy samples, preserving real scope.
func (s *State) removeLegacySamples() {
	domains := map[string]bool{}
	ids := map[string]bool{}
	for _, t := range s.Targets {
		if t.Demo {
			ids[t.ID] = true
			domains[t.Domain] = true
		}
	}
	targets := []Target{}
	for _, t := range s.Targets {
		if !ids[t.ID] {
			targets = append(targets, t)
		}
	}
	assets := []Asset{}
	for _, a := range s.Assets {
		if !ids[a.TargetID] {
			assets = append(assets, a)
		}
	}
	findings := []Finding{}
	for _, f := range s.Findings {
		sample := ids[f.TargetID]
		for d := range domains {
			if inScope(f.Host, d) {
				sample = true
			}
		}
		if !sample {
			findings = append(findings, f)
		}
	}
	scans := []Scan{}
	for _, sc := range s.Scans {
		if !sc.Demo && !ids[sc.TargetID] {
			scans = append(scans, sc)
		}
	}
	if len(ids) > 0 {
		events := []Event{}
		for _, e := range s.Events {
			if !legacySampleEvent(e, domains) {
				events = append(events, e)
			}
		}
		audit := []Event{}
		for _, e := range s.Audit {
			if !legacySampleEvent(e, domains) {
				audit = append(audit, e)
			}
		}
		s.Events, s.Audit = events, audit
		if s.Settings.Name == "Acme Security" {
			s.Settings.Name = "My workspace"
		}
	}
	s.Targets, s.Assets, s.Findings, s.Scans = targets, assets, findings, scans
	s.Demo = false
}

func legacySampleEvent(e Event, domains map[string]bool) bool {
	if e.Actor == "Alex Morgan" || strings.HasPrefix(e.Title, "Demo ") || e.Title == "Sample workspace created" {
		return true
	}
	for d := range domains {
		if strings.Contains(e.Detail, d) {
			return true
		}
	}
	return false
}
