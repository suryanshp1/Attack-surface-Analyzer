package main

import "testing"

func surfaceScan(id, started, ip, technology, expiry string) Scan {
	origin := "https://owned.example"
	return Scan{ID: id, TargetID: "target", Domain: "owned.example", Status: "completed", StartedAt: started, Checkpoint: Checkpoint{
		DNS: map[string][]string{"owned.example": {ip}}, PortResults: map[string][]int{ip: {443}}, ProbeResults: map[string]string{origin: "responded"},
		Assets: []Asset{{Host: "owned.example", IP: ip, Ports: []int{443}, Services: []Service{{URL: origin, Port: 443, Technologies: []string{technology}, CertificateExpiry: expiry}}}},
	}}
}

func TestSurfaceChangesUseImmutableSuccessfulObservations(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	old := surfaceScan("old", "2026-01-01T00:00:00Z", "1.1.1.1", "Nginx", "2026-03-01T00:00:00Z")
	current := surfaceScan("new", "2026-02-01T00:00:00Z", "8.8.8.8", "Apache", "2026-06-01T00:00:00Z")
	partial := current
	partial.ID = "partial"
	partial.Status = "partial"
	partial.StartedAt = "2026-01-31T00:00:00Z"
	s.state.Scans = []Scan{current, partial, old}
	s.state.Assets = current.Checkpoint.Assets
	s.normalize(&current, true)
	changes := 0
	for _, event := range s.state.Events {
		if event.Change != nil {
			changes++
			if event.Change.PreviousScanID != "old" || event.Change.ScanID != "new" || event.Change.TargetID != "target" {
				t.Fatal(event)
			}
		}
	}
	if changes != 3 {
		t.Fatalf("expected DNS, technology, certificate deltas; got %d", changes)
	}
	s.normalize(&current, true)
	repeated := 0
	for _, event := range s.state.Events {
		if event.Change != nil {
			repeated++
		}
	}
	if repeated != changes {
		t.Fatal("replayed scan duplicated changes")
	}
}

func TestSurfaceChangesIgnoreMissingBlockedAndPartialObservations(t *testing.T) {
	for _, mode := range []string{"missing", "blocked", "failed probe", "partial", "no baseline", "reordered"} {
		t.Run(mode, func(t *testing.T) {
			s := testServer(t)
			s.state = emptyState()
			old := surfaceScan("old", "2026-01-01T00:00:00Z", "1.1.1.1", "Nginx", "2026-03-01T00:00:00Z")
			current := surfaceScan("new", "2026-02-01T00:00:00Z", "1.1.1.1", "Apache", "2026-06-01T00:00:00Z")
			s.state.Scans = []Scan{old}
			switch mode {
			case "missing":
				current.Checkpoint.Assets[0].Services = nil
			case "blocked":
				current.Checkpoint.Assets[0].Blocked = true
			case "failed probe":
				current.Checkpoint.ProbeResults["https://owned.example"] = "failed"
			case "partial":
				current.Status = "partial"
			case "no baseline":
				s.state.Scans = nil
			case "reordered":
				current.Checkpoint.Assets[0].Services = old.Checkpoint.Assets[0].Services
			}
			s.normalize(&current, current.Status == "completed")
			for _, e := range s.state.Events {
				if e.Change != nil {
					t.Fatal("unknown data became drift", e)
				}
			}
		})
	}
}

func TestStructuredPortChangeDoesNotDuplicateLegacyEvent(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	old := surfaceScan("old", "2026-01-01T00:00:00Z", "1.1.1.1", "Nginx", "2026-03-01T00:00:00Z")
	current := surfaceScan("new", "2026-02-01T00:00:00Z", "1.1.1.1", "Nginx", "2026-03-01T00:00:00Z")
	current.Checkpoint.Assets[0].Ports = []int{443, 8443}
	current.Checkpoint.PortResults["1.1.1.1"] = []int{443, 8443}
	old.Checkpoint.Assets[0].ID = fingerprint("target", "owned.example")
	s.state.Scans = []Scan{old}
	s.state.Assets = old.Checkpoint.Assets
	s.normalize(&current, true)
	count := 0
	for _, e := range s.state.Events {
		if e.Kind == "port" {
			count++
			if e.Change == nil {
				t.Fatal("legacy event duplicated structured change")
			}
		}
	}
	if count != 1 {
		t.Fatal("expected one port delta", count)
	}
}
