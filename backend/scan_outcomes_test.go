package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPRecordsSilentAndFailedSiblingOrigins(t *testing.T) {
	for _, outcome := range []string{"silent", "failed", "forbidden", "rate_limited", "server_error"} {
		t.Run(outcome, func(t *testing.T) {
			cp := Checkpoint{Assets: []Asset{{Host: "owned.example", Ports: []int{443, 8443}}}}
			worker := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
				output := "{\"url\":\"https://owned.example\",\"status_code\":200}\n"
				if outcome != "silent" {
					status := map[string]int{"forbidden": 403, "rate_limited": 429, "server_error": 503}[outcome]
					output += fmt.Sprintf("{\"url\":\"https://owned.example:8443\",\"status_code\":%d,\"failed\":%t}\n", status, outcome == "failed")
				}
				return []byte(output), "", nil
			}}
			result, _, err := worker.probe(context.Background(), Claim{Target: Target{Domain: "owned.example"}}, cp, "", t.TempDir())
			expected := outcome
			if outcome == "silent" {
				expected = "unfinished"
			}
			if err == nil || result.ProbeResults["https://owned.example"] != "responded" || result.ProbeResults["https://owned.example:8443"] != expected || !contains(result.Blocked, "owned.example") || result.Assets[0].Blocked {
				t.Fatalf("lost origin failure or blocked healthy sibling: %#v %v", result, err)
			}
		})
	}
}

func TestHTTPPreservesProcessErrorWithCompleteRecords(t *testing.T) {
	failure := errors.New("scanner failed")
	worker := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		return []byte("{\"url\":\"https://owned.example\",\"status_code\":200}\n"), "", failure
	}}
	result, _, err := worker.probe(context.Background(), Claim{Target: Target{Domain: "owned.example"}}, Checkpoint{Assets: []Asset{{Host: "owned.example", Ports: []int{443}}}}, "", t.TempDir())
	if !errors.Is(err, failure) || len(result.Assets[0].Services) != 1 {
		t.Fatalf("lost process failure or observation: %v", err)
	}
}

func TestDetectionKeepsHealthySiblingEligible(t *testing.T) {
	worker := Worker{Templates: "templates"}
	manifest, err := worker.manifest()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, entry := range manifest.Templates {
		ids[entry.File] = entry.ID
	}
	worker.scannerCommand = func(_ context.Context, name string, args []string, _, _ string) ([]byte, string, error) {
		flags := map[string]string{}
		for i := 0; i+1 < len(args); i++ {
			flags[args[i]] = args[i+1]
		}
		data, e := os.ReadFile(flags["-l"])
		if e != nil {
			return nil, "", e
		}
		var output []byte
		for _, raw := range strings.Fields(string(data)) {
			if serviceOrigin(raw) != "https://owned.example" {
				return nil, "", errors.New("blocked origin was scanned")
			}
			for _, file := range strings.Split(flags["-t"], ",") {
				row, _ := json.Marshal(map[string]any{"template-id": ids[filepath.Base(file)], "url": raw, "matcher-status": false, "response": "HTTP/1.1 200 OK\r\n"})
				output = append(output, append(row, '\n')...)
			}
		}
		return output, "", nil
	}
	cp := Checkpoint{Blocked: []string{"owned.example"}, Assets: []Asset{{Host: "owned.example", URL: "https://owned.example", Services: []Service{{URL: "https://owned.example", Status: 200}, {URL: "https://owned.example:8443", Status: 403}}}}}
	result, _, err := worker.detect(context.Background(), Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Concurrency: 1, Rate: 5}}, cp, "", t.TempDir())
	if err != nil || len(result.DetectionRequired["https://owned.example"]) == 0 || len(result.ServiceCoverage["https://owned.example"]) == 0 || len(result.DetectionRequired["https://owned.example:8443"]) > 0 {
		t.Fatalf("incorrect service requirements/coverage: %#v %v", result, err)
	}
}

func TestPublicScanOutcomesAndLegacyUnknownCounts(t *testing.T) {
	cp := Checkpoint{ProbeResults: map[string]string{"https://owned.example": "responded", "https://owned.example:8443": "failed"}, DetectionRequired: map[string][]string{"https://owned.example": {"one", "two"}}, ServiceCoverage: map[string][]string{"https://owned.example": {"one"}}}
	sc := Scan{Status: "partial", Lease: "hidden-lease", Checkpoint: cp, Stages: []Stage{{Name: "HTTP probing", Status: "completed"}, {Name: "Detection", Status: "completed"}}}
	result := publicScan(sc)
	if result.Coverage.HTTP.Finished != 1 || result.Coverage.HTTP.Remaining != 1 || result.Coverage.Detection.Finished != 1 || result.Coverage.Detection.Remaining != 1 || result.Stages[0].CoverageStatus != "incomplete" || result.Stages[1].CoverageStatus != "incomplete" {
		t.Fatalf("coverage lost: %#v", result)
	}
	if result.Lease != "" || result.Checkpoint.ProbeResults != nil || sc.Stages[0].CoverageStatus != "" {
		t.Fatal("leaked private state or mutated stored stages")
	}
	legacy := publicScan(Scan{Status: "partial", Stages: []Stage{{Name: "Detection", Status: "completed"}}})
	if legacy.Coverage.HTTP != nil || legacy.Coverage.Detection != nil {
		t.Fatal("invented legacy denominators")
	}
}

func TestResumePreviewMatchesMutationAndJSONStorage(t *testing.T) {
	for _, restart := range []string{"Discovery", "DNS resolution", "Port discovery", "HTTP probing", "Endpoint crawling", "Detection"} {
		t.Run(restart, func(t *testing.T) {
			s := testServer(t)
			s.state = emptyState()
			s.liveEnabled, s.allowUnverified = true, true
			s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "pending"}}
			sc := newScan(s.state.Targets[0], "Manual", 5)
			sc.ID = "old"
			sc.Status = "partial"
			for i := range sc.Stages {
				sc.Stages[i].Status = "completed"
				sc.Stages[i].StartedAt = "2026-10-19T00:00:00Z"
				sc.Stages[i].FinishedAt = "2026-10-19T00:01:00Z"
			}
			sc.Checkpoint.IncompleteStages = map[string]string{restart: "unfinished"}
			sc.Checkpoint.ProbeResults = map[string]string{"https://owned.example": "responded"}
			s.state.Scans = []Scan{sc}
			preview := publicScan(sc).Resume
			response := request(s, "POST", "/api/scans/old/retry", `{}`)
			if response.Code != 200 || preview == nil {
				t.Fatal(response.Code, response.Body.String())
			}
			retry := s.state.Scans[0]
			if retry.ParentScanID != "old" || retry.Progress != preview.RetainedStages*100/len(retry.Stages) || retry.Stages[preview.RetainedStages].Name != restart || retry.Stages[preview.RetainedStages].Status != "pending" || retry.Stages[preview.RetainedStages].StartedAt != "" {
				t.Fatalf("preview and execution differ: %#v %#v", preview, retry)
			}
			saved, err := os.ReadFile(s.file)
			if err != nil {
				t.Fatal(err)
			}
			var loaded State
			if err = json.Unmarshal(saved, &loaded); err != nil {
				t.Fatal(err)
			}
			if loaded.Scans[0].ParentScanID != "old" || loaded.Scans[1].Checkpoint.ProbeResults["https://owned.example"] != "responded" {
				t.Fatal("JSON storage lost additive fields or original history")
			}
		})
	}
}

func TestValidateOriginOutcomesRejectsUnsafeAndUnknownValues(t *testing.T) {
	for _, cp := range []Checkpoint{
		{ProbeResults: map[string]string{"https://outside.example": "responded"}},
		{ProbeResults: map[string]string{"https://owned.example?token=secret": "failed"}},
		{ProbeResults: map[string]string{"https://owned.example": "arbitrary detail"}},
		{DetectionRequired: map[string][]string{"https://owned.example/path": {"one"}}},
	} {
		if validateCheckpoint(cp, "owned.example") == nil {
			t.Fatal("accepted unsafe outcome")
		}
	}
}
