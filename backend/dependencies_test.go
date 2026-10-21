package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cleanRetireOutput(args []string) []byte {
	files, _ := os.ReadDir(args[1])
	var output []byte
	for _, f := range files {
		line, _ := json.Marshal(map[string]any{"file": f.Name(), "results": []any{}})
		output = append(output, append(line, '\n')...)
	}
	marker, _ := json.Marshal(map[string]any{"complete": true, "database": retireDatabase})
	return append(output, append(marker, '\n')...)
}

func libraryFinding(source string) Finding {
	return Finding{Host: "owned.example", MatchedAt: source, Template: "retire:jquery:fixture", Dependency: &DependencyObservation{Name: "jquery", Version: "1.12.4", Detection: "filecontent", Database: retireDatabase}}
}

func TestDependencyCoverageRequiresOriginalFileAndCompleteReport(t *testing.T) {
	source := "https://owned.example/app.js"
	name := fingerprint(source) + ".js"
	known := libraryFinding(source)
	c := Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Checkpoint: Checkpoint{KnownLibraries: []Finding{known, libraryFinding("https://owned.example/other.js")}}}}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("clean"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"complete", "truncated", "failure", "wrong database", "failed download", "unknown file", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			failed := map[string]bool{}
			w := Worker{scannerCommand: func(_ context.Context, tool string, args []string, proxy, _ string) ([]byte, string, error) {
				if tool != "retire" || proxy != "" {
					t.Fatal("unexpected scanner/network path")
				}
				output := cleanRetireOutput(args)
				switch mode {
				case "truncated":
					output = []byte(`{"file":"` + name + `","results":[]}` + "\n")
				case "failure":
					return output, "", errors.New("scanner stopped")
				case "wrong database":
					output = []byte(`{"complete":true,"database":"wrong"}` + "\n")
				case "unknown file":
					output = []byte(`{"file":"../secret.js","results":[]}` + "\n")
				case "duplicate":
					output = append(output, output...)
				}
				return output, "", nil
			}}
			if mode == "failed download" {
				failed["owned.example"] = true
			}
			cp, _, err := w.analyzeDependencies(context.Background(), c, Checkpoint{}, map[string]string{name: source}, failed, dir, dir)
			if mode == "complete" {
				if err != nil || !contains(cp.LibraryCoverage[source], known.Template) || len(cp.LibraryCoverage["https://owned.example/other.js"]) != 0 {
					t.Fatal("incorrect file coverage", cp.LibraryCoverage, err)
				}
			} else if len(cp.LibraryCoverage) != 0 || (mode != "failed download" && err == nil) {
				t.Fatal("incomplete report credited coverage", mode, cp.LibraryCoverage, err)
			}
		})
	}
}

func TestDependencyObservationsSurviveFailureWithoutRawContents(t *testing.T) {
	source := "https://owned.example/app.js"
	name := fingerprint(source) + ".js"
	output := `{"file":"` + name + `","results":[{"component":"jquery","version":"1.12.4","detection":"filecontent","vulnerabilities":[{"below":"3.5.0","severity":"medium","identifiers":{"CVE":["CVE-2020-11022"]},"cwe":["CWE-79"]}]}]}` + "\n"
	w := Worker{scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) {
		return []byte(output), "", errors.New("interrupted")
	}}
	cp, _, err := w.analyzeDependencies(context.Background(), Claim{Target: Target{Domain: "owned.example"}}, Checkpoint{}, map[string]string{name: source}, nil, t.TempDir(), t.TempDir())
	if err == nil || len(cp.Findings) != 1 || len(cp.LibraryCoverage) != 0 {
		t.Fatal(cp, err)
	}
	f := cp.Findings[0]
	if f.Dependency.Version != "1.12.4" || !contains(f.CVEs, "CVE-2020-11022") || f.Tool != "retire" {
		t.Fatal(f)
	}
	if validateCheckpoint(cp, "owned.example") != nil {
		t.Fatal("valid dependency rejected")
	}
}

func TestDependencyLifecycleRequiresExactFileAndTwoCleanScans(t *testing.T) {
	s := testServer(t)
	s.state = emptyState()
	source := "https://owned.example/app.js"
	f := libraryFinding(source)
	f.ID, f.TargetID, f.Status, f.FirstSeen = fingerprint("target", f.Template, f.Host, f.MatchedAt), "target", "open", "2026-01-01T00:00:00Z"
	s.state.Findings = []Finding{f}
	sc := Scan{TargetID: "target", Checkpoint: Checkpoint{Coverage: map[string][]string{f.Host: {f.Template}}, ServiceCoverage: map[string][]string{}, LibraryCoverage: map[string][]string{"https://owned.example/other.js": {f.Template}}}}
	s.normalize(&sc, true)
	s.normalize(&sc, true)
	if s.state.Findings[0].MissingScans != 0 {
		t.Fatal("sibling file resolved unchecked finding")
	}
	sc.Checkpoint.LibraryCoverage[source] = []string{f.Template}
	s.normalize(&sc, false)
	if s.state.Findings[0].MissingScans != 0 {
		t.Fatal("partial scan advanced lifecycle")
	}
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "open" {
		t.Fatal("resolved after one scan")
	}
	s.normalize(&sc, true)
	if s.state.Findings[0].Status != "resolved" {
		t.Fatal("did not resolve after two covered scans")
	}
	sc.Checkpoint.Findings = []Finding{f}
	s.normalize(&sc, false)
	if s.state.Findings[0].Status != "open" || s.state.Findings[0].FirstSeen != f.FirstSeen {
		t.Fatal("rediscovery lost history")
	}
}

func TestVulnerabilityMetadataValidation(t *testing.T) {
	for _, score := range []float64{-1, 11, math.Inf(1), math.NaN()} {
		if validCVSSScore(&score) != nil {
			t.Fatal("invalid score accepted")
		}
	}
	if got := normalizedIDs([]string{"cve-2020-11022", "CVE-2020-11022", "bogus"}, cvePattern); len(got) != 1 {
		t.Fatal(got)
	}
	cp := Checkpoint{Findings: []Finding{{Host: "owned.example", CVEs: []string{"https://evil.invalid"}}}}
	if validateCheckpoint(cp, "owned.example") == nil {
		t.Fatal("invalid identifier accepted")
	}
	cp.Findings[0].CVEs = []string{"CVE-2020-11022"}
	cp.Findings[0].CVSSMetrics = "CVSS:3.1/\nsecret"
	if validateCheckpoint(cp, "owned.example") == nil {
		t.Fatal("invalid vector accepted")
	}
	if strings.Contains(normalizedCVSSMetrics("invalid"), "invalid") {
		t.Fatal("invalid vector retained")
	}
}

func TestNucleiMetadataAndJSONPersistence(t *testing.T) {
	w := Worker{Templates: "templates"}
	manifest, err := w.manifest()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, entry := range manifest.Templates {
		ids[entry.File] = entry.ID
	}
	w.scannerCommand = func(_ context.Context, name string, args []string, _, _ string) ([]byte, string, error) {
		flags := map[string]string{}
		for i := 0; i+1 < len(args); i++ {
			flags[args[i]] = args[i+1]
		}
		var out []byte
		for _, file := range strings.Split(flags["-t"], ",") {
			row := map[string]any{"template-id": ids[filepath.Base(file)], "url": "https://owned.example", "response": "HTTP/1.1 200 OK\r\n", "matcher-status": ids[filepath.Base(file)] == "git-config", "info": map[string]any{"name": "Fixture exposure", "severity": "info", "classification": map[string]any{"cve-id": []string{"CVE-2020-11022"}, "cwe-id": []string{"CWE-79"}, "cvss-score": 0, "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}}
			b, _ := json.Marshal(row)
			out = append(out, append(b, '\n')...)
		}
		return out, "", nil
	}
	cp, _, err := w.detect(context.Background(), Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{Rate: 20, Concurrency: 5}}, Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example"}}}, "", t.TempDir())
	if err != nil || len(cp.Findings) != 1 {
		t.Fatal(cp.Findings, err)
	}
	f := cp.Findings[0]
	if f.CVSSScore == nil || *f.CVSSScore != 0 || len(f.CVEs) != 1 || len(f.CWEs) != 1 || f.CVSSMetrics == "" {
		t.Fatal("Nuclei classification lost", f)
	}
	s := testServer(t)
	s.state = emptyState()
	s.state.Findings = []Finding{f}
	s.state.Events = []Event{{ID: "change", Change: &SurfaceChange{TargetID: "target", ScanID: "new", PreviousScanID: "old", Host: "owned.example", Field: "dnsAddresses", Before: []string{"1.1.1.1"}, After: []string{"8.8.8.8"}}}}
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.file)
	if err != nil {
		t.Fatal(err)
	}
	var restored State
	if err = json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Findings[0].CVSSScore == nil || *restored.Findings[0].CVSSScore != 0 || restored.Events[0].Change.PreviousScanID != "old" {
		t.Fatal("JSON round trip lost additive metadata")
	}
}

func TestExpandedProfilePreservesOlderScanTemplateSets(t *testing.T) {
	if sc := newScan(Target{ID: "target", Domain: "owned.example"}, "Manual", 20); sc.TemplateSet != "v10.5.0-curated-3" {
		t.Fatal(sc.TemplateSet)
	}
	for _, profile := range []string{"v10.5.0-curated-1", "v10.5.0-curated-2", "v10.5.0-curated-3"} {
		t.Run(profile, func(t *testing.T) {
			w := Worker{Templates: "templates", scannerCommand: func(context.Context, string, []string, string, string) ([]byte, string, error) { return nil, "", nil }}
			cp, _, _ := w.detect(context.Background(), Claim{Target: Target{Domain: "owned.example"}, Scan: Scan{TemplateSet: profile, Rate: 20, Concurrency: 5}}, Checkpoint{Assets: []Asset{{Host: "owned.example", URL: "https://owned.example"}}}, "", t.TempDir())
			hasNew := contains(cp.Templates, "springboot-health") || contains(cp.Templates, "springboot-mappings")
			if hasNew != (profile == "v10.5.0-curated-3") {
				t.Fatal("resume changed profile", profile, cp.Templates)
			}
		})
	}
}
