package main

import (
	"encoding/json"
	"testing"
)

func TestSubdomainTakeoverTwoScanResolutionAndReopening(t *testing.T) {
	s := testServer(t)
	sc1 := &Scan{
		ID:       "scan-1",
		TargetID: "target-1",
		Domain:   "example.com",
		Status:   "completed",
		Checkpoint: Checkpoint{
			Takeovers: []SubdomainTakeover{
				{
					Subdomain:       "sub.example.com",
					CNAME:           "vulnerable.s3.amazonaws.com",
					ServiceProvider: "AWS S3",
				},
			},
		},
	}

	// 1. First scan detects takeover
	s.normalize(sc1, true)
	if len(s.state.Takeovers) != 1 {
		t.Fatalf("expected 1 takeover, got %d", len(s.state.Takeovers))
	}
	to := s.state.Takeovers[0]
	if to.Status != "open" || to.MissingScans != 0 {
		t.Fatalf("expected open takeover with MissingScans=0, got %+v", to)
	}

	// 2. Second scan (successful) does NOT detect the takeover
	sc2 := &Scan{
		ID:         "scan-2",
		TargetID:   "target-1",
		Domain:     "example.com",
		Status:     "completed",
		Checkpoint: Checkpoint{},
	}
	s.normalize(sc2, true)
	to = s.state.Takeovers[0]
	if to.Status != "open" {
		t.Fatalf("takeover should remain open after only 1 missing scan, got status=%s", to.Status)
	}
	if to.MissingScans != 1 {
		t.Fatalf("expected MissingScans=1, got %d", to.MissingScans)
	}

	// 3. Third scan (successful) still does NOT detect the takeover -> Resolves
	sc3 := &Scan{
		ID:         "scan-3",
		TargetID:   "target-1",
		Domain:     "example.com",
		Status:     "completed",
		Checkpoint: Checkpoint{},
	}
	s.normalize(sc3, true)
	to = s.state.Takeovers[0]
	if to.Status != "resolved" {
		t.Fatalf("takeover should be resolved after 2 missing scans, got status=%s", to.Status)
	}
	if to.MissingScans != 2 {
		t.Fatalf("expected MissingScans=2, got %d", to.MissingScans)
	}

	// 4. Fourth scan detects the takeover again -> Reopens
	sc4 := &Scan{
		ID:       "scan-4",
		TargetID: "target-1",
		Domain:   "example.com",
		Status:   "completed",
		Checkpoint: Checkpoint{
			Takeovers: []SubdomainTakeover{
				{
					Subdomain:       "sub.example.com",
					CNAME:           "vulnerable.s3.amazonaws.com",
					ServiceProvider: "AWS S3",
				},
			},
		},
	}
	s.normalize(sc4, true)
	to = s.state.Takeovers[0]
	if to.Status != "open" {
		t.Fatalf("takeover should reopen to status=open, got %s", to.Status)
	}
	if to.MissingScans != 0 {
		t.Fatalf("expected MissingScans reset to 0, got %d", to.MissingScans)
	}
	if to.ReopenCount != 1 {
		t.Fatalf("expected ReopenCount=1, got %d", to.ReopenCount)
	}
}

func TestSubdomainTakeoverJSONSerialization(t *testing.T) {
	to := SubdomainTakeover{
		ID:              "to-1",
		ScanID:          "scan-1",
		Subdomain:       "sub.example.com",
		CNAME:           "vulnerable.s3.amazonaws.com",
		ServiceProvider: "AWS S3",
		Status:          "open",
		FirstSeen:       "2026-10-18T00:00:00Z",
		LastSeen:        "2026-10-18T01:00:00Z",
		ReopenCount:     1,
		MissingScans:    1,
	}
	data, err := json.Marshal(to)
	if err != nil {
		t.Fatal(err)
	}
	var loaded SubdomainTakeover
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.MissingScans != 1 {
		t.Fatalf("expected MissingScans=1 after unmarshal, got %d", loaded.MissingScans)
	}
}
