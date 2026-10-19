package main

import (
	"errors"
	"fmt"
	"sort"
)

// resumeStage is shared by the public preview and the mutation. It understands
// old stage layouts by name, rather than assuming the current stage count.
func resumeStage(sc Scan) int {
	first := len(sc.Stages)
	for i, stage := range sc.Stages {
		if stage.Status != "completed" || sc.Checkpoint.IncompleteStages[stage.Name] != "" ||
			stage.Name == "Endpoint crawling" && len(sc.Checkpoint.CrawlIncomplete) > 0 ||
			stage.Name == "Port discovery" && len(sc.Checkpoint.PortIncomplete) > 0 {
			if i < first {
				first = i
			}
		}
	}
	if first == len(sc.Stages) {
		for i, stage := range sc.Stages {
			if stage.Name == "HTTP probing" {
				return i
			}
		}
	}
	return first
}

func scanResumePlan(sc Scan) *ResumePlan {
	if sc.Status != "partial" && sc.Status != "failed" {
		return nil
	}
	first := resumeStage(sc)
	if first == len(sc.Stages) {
		return nil
	}
	policy := "Completed port batches, crawl seeds and service/template checks can be reused where still valid."
	switch sc.Stages[first].Name {
	case "Discovery", "DNS resolution":
		policy = "Network results and downstream checkpoints will be rebuilt after discovery or DNS is retried."
	case "Port discovery", "HTTP probing":
		policy = "Completed port batches are reused. HTTP responses, crawls and detection checks will be rebuilt."
	}
	return &ResumePlan{sc.Stages[first].Name, first, len(sc.Stages) - first, policy}
}

func validateServiceOutcomes(cp Checkpoint, root string) error {
	if len(cp.ProbeResults) > 10000 || len(cp.DetectionRequired) > 10000 {
		return errors.New("Service outcome limit exceeded")
	}
	validOrigin := func(origin string) bool {
		_, ok := scopedEndpoint(origin, root)
		return ok && serviceOrigin(origin) == origin
	}
	for origin, result := range cp.ProbeResults {
		if !validOrigin(origin) {
			return errors.New("HTTP outcome escaped service scope")
		}
		switch result {
		case "responded", "forbidden", "rate_limited", "server_error", "failed", "unfinished":
		default:
			return errors.New("Invalid HTTP outcome")
		}
	}
	for origin, templates := range cp.DetectionRequired {
		if !validOrigin(origin) || len(templates) > 200 {
			return errors.New("Detection requirements escaped scope or exceed limits")
		}
		for _, template := range templates {
			if len(template) == 0 || len(template) > 200 {
				return errors.New("Invalid detection template ID")
			}
		}
	}
	return nil
}

func projectScanCoverage(sc *Scan) {
	cp := sc.Checkpoint
	coverage := ScanCoverage{CrawlFinished: len(cp.CrawlResults), CrawlRemaining: len(cp.CrawlIncomplete), PortFinished: len(cp.PortResults), PortRemaining: len(cp.PortIncomplete)}
	if cp.ProbeResults != nil {
		coverage.HTTP = &CheckCoverage{}
		origins := make([]string, 0, len(cp.ProbeResults))
		for origin := range cp.ProbeResults {
			origins = append(origins, origin)
		}
		sort.Strings(origins)
		for _, origin := range origins {
			result := cp.ProbeResults[origin]
			if result == "responded" {
				coverage.HTTP.Finished++
			} else {
				coverage.HTTP.Remaining++
				coverage.ServiceIssueCount++
				if len(coverage.ServiceIssues) < 50 {
					coverage.ServiceIssues = append(coverage.ServiceIssues, ServiceIssue{origin, result})
				}
			}
		}
	}
	if cp.DetectionRequired != nil {
		coverage.Detection = &CheckCoverage{}
		for origin, required := range cp.DetectionRequired {
			for _, template := range dedupeStrings(required) {
				if contains(cp.ServiceCoverage[origin], template) {
					coverage.Detection.Finished++
				} else {
					coverage.Detection.Remaining++
				}
			}
		}
	}
	sc.Coverage = coverage
	sc.Resume = scanResumePlan(*sc)
	for i := range sc.Stages {
		stage := &sc.Stages[i]
		// Public projections must not trust cached/persisted presentation fields.
		stage.CoverageStatus, stage.Issue = "unknown", ""
		issue := cp.IncompleteStages[stage.Name]
		switch stage.Name {
		case "Port discovery":
			if len(cp.PortIncomplete) > 0 {
				issue = fmt.Sprintf("Port checks remain unfinished for %d hosts.", len(cp.PortIncomplete))
			}
		case "Endpoint crawling":
			if len(cp.CrawlIncomplete) > 0 {
				issue = fmt.Sprintf("Bounded crawls remain unfinished for %d services.", len(cp.CrawlIncomplete))
			}
		case "HTTP probing":
			if coverage.HTTP != nil && coverage.HTTP.Remaining > 0 {
				issue = fmt.Sprintf("%d service origins have failed, blocked or unfinished HTTP checks.", coverage.HTTP.Remaining)
			} else if len(coverageBlockers(cp)) > 0 && issue == "" {
				issue = "Some hosts have failed or incomplete coverage. Review the diagnostic log."
			}
		case "Detection":
			if coverage.Detection != nil && coverage.Detection.Remaining > 0 {
				issue = fmt.Sprintf("%d required service/template checks remain unfinished.", coverage.Detection.Remaining)
			}
			if coverage.ServiceIssueCount > 0 {
				issue += " Detection is unavailable for services with unsuccessful HTTP checks."
			}
		}
		if issue != "" {
			stage.CoverageStatus, stage.Issue = "incomplete", redact(capString(issue, 1000))
		} else if stage.Status == "completed" {
			stage.CoverageStatus = "finished"
		}
	}
}
