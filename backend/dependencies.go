package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const retireDatabase = "e5e228659bbcaea7ba85536a2ef8d4fb97b366e9"

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
var cwePattern = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
var componentPattern = regexp.MustCompile(`^[a-zA-Z0-9@/_.-]{1,100}$`)
var componentVersionPattern = regexp.MustCompile(`^[a-zA-Z0-9_.+-]{1,80}$`)

func normalizedIDs(values []string, pattern *regexp.Regexp) []string {
	var out []string
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if pattern.MatchString(value) && !contains(out, value) {
			out = append(out, value)
		}
		if len(out) == 20 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func validCVSSScore(score *float64) *float64 {
	if score == nil || math.IsNaN(*score) || math.IsInf(*score, 0) || *score < 0 || *score > 10 {
		return nil
	}
	return score
}

func normalizedCVSSMetrics(value string) string {
	if len(value) > 200 || (!strings.HasPrefix(value, "CVSS:3.0/") && !strings.HasPrefix(value, "CVSS:3.1/") && !strings.HasPrefix(value, "CVSS:4.0/")) {
		return ""
	}
	if strings.ContainsAny(value, "\r\n\t ") {
		return ""
	}
	return value
}

// Runs the dependency-free engine over existing files, with no network or script execution.
// Coverage is credited only after every source file was reported and the final marker arrived.
func (w *Worker) analyzeDependencies(ctx context.Context, c Claim, cp Checkpoint, sources map[string]string, failed map[string]bool, jsDir, dir string) (Checkpoint, string, error) {
	cp.LibraryCoverage = map[string][]string{}
	completed, seen := false, map[string]bool{}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	findingsBefore := len(cp.Findings)
	logs, runErr := w.runScannerStream(ctx, "retire", []string{"--path", jsDir}, "", dir, func(line []byte) error {
		var row struct {
			File     string `json:"file"`
			Complete bool   `json:"complete"`
			Database string `json:"database"`
			Results  []struct {
				Component       string `json:"component"`
				Version         string `json:"version"`
				Detection       string `json:"detection"`
				Vulnerabilities []struct {
					Below       string   `json:"below"`
					AtOrAbove   string   `json:"atOrAbove"`
					Severity    string   `json:"severity"`
					Info        []string `json:"info"`
					Identifiers struct {
						CVEs     []string `json:"CVE"`
						GithubID string   `json:"githubID"`
						RetID    string   `json:"retid"`
					} `json:"identifiers"`
					CWEs []string `json:"cwe"`
				} `json:"vulnerabilities"`
			} `json:"results"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return err
		}
		if completed {
			return errors.New("Retire.js output after completion")
		}
		if row.Complete {
			if row.Database != retireDatabase || row.File != "" {
				return errors.New("Retire.js database mismatch")
			}
			completed = true
			return nil
		}
		source, ok := sources[row.File]
		if !ok || filepath.Base(row.File) != row.File || seen[row.File] {
			return errors.New("Retire.js reported unexpected file")
		}
		seen[row.File] = true
		u, ok := scopedEndpoint(source, c.Target.Domain)
		if !ok {
			return errors.New("Retire.js source escaped scope")
		}
		for _, component := range row.Results {
			if !componentPattern.MatchString(component.Component) || !componentVersionPattern.MatchString(component.Version) {
				return errors.New("Invalid dependency observation")
			}
			switch component.Detection {
			case "filecontent", "filecontentreplace", "hash":
			default:
				return errors.New("Unsupported dependency detection")
			}
			for _, advisory := range component.Vulnerabilities {
				if len(cp.Findings) >= 2000 {
					return errors.New("finding cap exceeded")
				}
				cves := normalizedIDs(advisory.Identifiers.CVEs, cvePattern)
				identity := strings.Join(cves, ",")
				if identity == "" {
					identity = capString(advisory.Identifiers.GithubID+":"+advisory.Identifiers.RetID, 200)
				}
				if identity == ":" {
					identity = advisory.AtOrAbove + ":" + advisory.Below
				}
				template := "retire:" + component.Component + ":" + fingerprint(identity)
				duplicate := false
				for _, f := range cp.Findings {
					if f.Template == template && f.MatchedAt == source {
						duplicate = true
						break
					}
				}
				if duplicate {
					continue
				}
				severity := advisory.Severity
				switch severity {
				case "critical", "high", "medium", "low":
				default:
					severity = "info"
				}
				cp.Findings = append(cp.Findings, Finding{
					Host: u.Hostname(), Template: template, MatchedAt: source,
					Title:    "Vulnerable JavaScript library: " + component.Component + " " + component.Version,
					Severity: severity, Category: "vulnerability", Tool: "retire", StageName: "JavaScript secrets",
					Description: "Static Retire.js analysis identified a browser library version matching a known advisory. Exploit reachability has not been tested. This is an observed library, not a complete application dependency inventory.",
					Remediation: "Upgrade " + component.Component + " to a supported release that fixes the referenced advisory and rebuild the public JavaScript bundle.",
					CVEs:        cves, CWEs: normalizedIDs(advisory.CWEs, cwePattern),
					Dependency: &DependencyObservation{Name: component.Component, Version: component.Version, Detection: component.Detection, Database: retireDatabase},
					Evidence:   fmt.Sprintf("URL: %s\nComponent: %s\nVersion: %s\nDetection: %s\nCVE: %s\nAdvisory snapshot: %s\nNo JavaScript execution or exploit validation performed.", source, component.Component, component.Version, component.Detection, strings.Join(cves, ", "), retireDatabase),
				})
			}
		}
		return nil
	})
	if runErr == nil && (!completed || len(seen) != len(sources)) {
		runErr = errors.New("Retire.js analysis incomplete")
	}
	if runErr == nil {
		for _, f := range append(append([]Finding{}, c.Scan.Checkpoint.KnownLibraries...), cp.Findings...) {
			u, err := url.Parse(f.MatchedAt)
			if err != nil || failed[f.Host] || u.Hostname() != f.Host || !strings.HasPrefix(f.Template, "retire:") {
				continue
			}
			if sources[fingerprint(f.MatchedAt)+".js"] != f.MatchedAt {
				continue
			}
			// A new advisory snapshot must not silently retire rules from an older snapshot.
			if f.Dependency == nil || f.Dependency.Database != retireDatabase {
				continue
			}
			cp.LibraryCoverage[f.MatchedAt] = append(cp.LibraryCoverage[f.MatchedAt], f.Template)
		}
	}
	return cp, fmt.Sprintf("Retire.js analyzed %d/%d downloaded files; %d dependency findings; advisory snapshot %s. %s", len(seen), len(sources), len(cp.Findings)-findingsBefore, retireDatabase, logs), runErr
}
