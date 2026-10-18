package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type workerAPIError struct {
	status  int
	message string
}

func (e *workerAPIError) Error() string { return fmt.Sprintf("API %d: %s", e.status, e.message) }

func scanStageBudget(ctx context.Context, sc Scan, stage int, cp Checkpoint) time.Duration {
	wanted := 7 * time.Minute
	workers := scanConcurrency(sc, 10)
	switch sc.Stages[stage].Name {
	case "Port discovery":
		wanted = portStageTimeout(cp, sc.Rate)
	case "Endpoint crawling":
		wanted = crawlStageTimeout(cp, sc)
	case "DNS resolution":
		wanted = min(20*time.Minute, max(wanted, time.Duration((len(cp.Hosts)+workers-1)/workers)*20*time.Second+time.Duration(len(cp.Hosts))*4*time.Second/time.Duration(max(1, sc.Rate))))
	case "HTTP probing", "TLS assessment", "TLS inspection":
		services := 0
		for _, a := range cp.Assets {
			services += max(1, len(a.Services), len(a.Ports))
		}
		wanted = min(20*time.Minute, max(wanted, time.Duration((services+workers-1)/workers)*25*time.Second))
	case "Detection":
		wanted = min(20*time.Minute, max(wanted, time.Duration(len(crawlSeeds(cp)))*14*4*time.Second/time.Duration(max(1, sc.Rate))))
	}
	if deadline, ok := ctx.Deadline(); ok {
		// Each downstream stage gets a chance to collect observations and commit.
		reserve := 10 * time.Second
		for _, next := range sc.Stages[stage+1:] {
			if next.Status != "completed" {
				reserve += 15 * time.Second
			}
		}
		wanted = min(wanted, max(time.Millisecond, time.Until(deadline)-reserve))
	}
	return wanted
}

func (w *Worker) runScanner(ctx context.Context, name string, args []string, proxy, dir string) ([]byte, string, error) {
	if w.scannerCommand != nil {
		return w.scannerCommand(ctx, name, args, proxy, dir)
	}
	return command(ctx, name, args, proxy, dir)
}

func serviceTemplatesCovered(cp Checkpoint, origin string, templates []string) bool {
	for _, template := range templates {
		if !contains(cp.ServiceCoverage[origin], template) {
			return false
		}
	}
	return true
}

func detectionBatchBudget(services, templates, rate int) time.Duration {
	// Leave room for multiple template requests, pacing and one request retry.
	return min(10*time.Minute, max(time.Minute, time.Duration(services*templates)*max(time.Second/time.Duration(max(rate, 1)), time.Second)*4+30*time.Second))
}

func evaluateTakeovers(ctx context.Context, sc Scan, hosts []string, check func(context.Context, string) (*SubdomainTakeover, error)) ([]SubdomainTakeover, error) {
	type result struct {
		takeover *SubdomainTakeover
		err      error
	}
	jobs := make(chan string, len(hosts))
	results := make(chan result, scanConcurrency(sc, 10))
	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)
	var wg sync.WaitGroup
	for i := 0; i < min(len(hosts), scanConcurrency(sc, 10)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if ctx.Err() != nil {
					return
				}
				guard := 8*time.Second + time.Duration(scanConcurrency(sc, 10))*4*time.Second/time.Duration(max(sc.Rate, 1))
				lookupCtx, cancel := context.WithTimeout(ctx, guard)
				takeover, err := check(lookupCtx, host)
				cancel()
				results <- result{takeover, err}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	var takeovers []SubdomainTakeover
	failed := 0
	for result := range results {
		if result.takeover != nil {
			takeovers = append(takeovers, *result.takeover)
		}
		if result.err != nil {
			failed++
		}
	}
	var err error
	if failed > 0 {
		err = fmt.Errorf("takeover DNS checks incomplete for %d hosts", failed)
	}
	return takeovers, errors.Join(err, ctx.Err())
}

// A killed subprocess can leave its last JSONL record unfinished. Keep earlier records.
func completeScannerRecords(output []byte, err error) []byte {
	if err == nil {
		return output
	}
	n := bytes.LastIndexByte(output, '\n')
	if json.Valid(output[n+1:]) {
		return output
	}
	return output[:n+1]
}

func setStageIssue(cp *Checkpoint, stage string, err error) {
	if err == nil {
		delete(cp.IncompleteStages, stage)
		return
	}
	if cp.IncompleteStages == nil {
		cp.IncompleteStages = map[string]string{}
	}
	cp.IncompleteStages[stage] = capString(redact(err.Error()), 1000)
}

func scanConcurrency(sc Scan, ceiling int) int {
	return min(max(sc.Concurrency, 1), ceiling)
}

// Use a short detached commit window so a stage deadline does not discard observations.
// The API still checks the current lease and scope before accepting the checkpoint.
func (w *Worker) checkpoint(ctx context.Context, c Claim, name string, cp Checkpoint, log string) (resultErr error) {
	if w.API == "" {
		return nil
	}
	for stage, st := range c.Scan.Stages {
		if st.Name != name {
			continue
		}
		started := time.Now()
		defer func() { GlobalTelemetry.RecordCheckpoint(time.Since(started), resultErr != nil) }()
		payload := w.payload(c.Scan)
		payload["stage"], payload["status"], payload["checkpoint"], payload["log"] = stage, "progress", cp, log
		commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			err = w.call(commitCtx, "/internal/stage", payload, nil)
			if err == nil {
				return nil
			}
			var apiErr *workerAPIError
			var networkErr net.Error
			if errors.As(err, &apiErr) {
				if apiErr.status < 500 {
					return err
				}
			} else if !errors.As(err, &networkErr) {
				return err
			}
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-commitCtx.Done():
				timer.Stop()
				return err
			case <-timer.C:
			}
		}
		return err
	}
	return nil
}

// stageFindingSummary leads the stage log so the 4,000-char log cap truncates
// scanner noise, not the findings a stage produced.
func stageFindingSummary(stage string, before int, cp Checkpoint) string {
	added := cp.Findings[min(max(before, 0), len(cp.Findings)):]
	if len(added) == 0 {
		return fmt.Sprintf("[Findings] %s: no new findings (%d total).", stage, len(cp.Findings))
	}
	lines := []string{fmt.Sprintf("[Findings] %s: %d new (%d total).", stage, len(added), len(cp.Findings))}
	for i, f := range added {
		if i == 10 {
			lines = append(lines, fmt.Sprintf("… %d more in Findings.", len(added)-10))
			break
		}
		lines = append(lines, fmt.Sprintf("- %s (%s) on %s", capString(f.Title, 120), f.Severity, f.Host))
	}
	return strings.Join(lines, "\n")
}
