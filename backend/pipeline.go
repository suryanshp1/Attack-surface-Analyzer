package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func (w *Worker) runScannerStream(ctx context.Context, name string, args []string, proxy, dir string, onLine func([]byte) error) (string, error) {
	if w.scannerCommand != nil {
		out, logs, err := w.scannerCommand(ctx, name, args, proxy, dir)
		_, streamErr := streamLines(bytes.NewReader(out), 2<<20, onLine)
		return logs, errors.Join(err, streamErr)
	}
	return commandStream(ctx, name, args, proxy, dir, onLine)
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
			if err == nil || !retryableWorkerError(err) {
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

func retryableWorkerError(err error) bool {
	var apiErr *workerAPIError
	if errors.As(err, &apiErr) {
		return apiErr.status >= 500
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// The API lease is 30 s; stop well before it lapses so a replacement worker
// never overlaps with this one.
const heartbeatSafetyWindow = 20 * time.Second

func heartbeatShouldStop(err error, lastOK, now time.Time) bool {
	if err == nil {
		return false
	}
	var apiErr *workerAPIError
	if errors.As(err, &apiErr) && apiErr.status < 500 {
		return true
	}
	return now.Sub(lastOK) > heartbeatSafetyWindow
}

// commitStage retries transient failures. Re-sending a completed stage is
// accepted by the API and stored under the same content-addressed evidence key.
func (w *Worker) commitStage(ctx context.Context, payload map[string]any) error {
	commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer cancel()
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if err = w.call(commitCtx, "/internal/stage", payload, nil); err == nil || !retryableWorkerError(err) {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 250 * time.Millisecond)
		select {
		case <-commitCtx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
	return err
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

// streamLines delivers complete lines as they arrive. Lines over maxLine are
// dropped and counted; a final fragment is delivered only if it is complete JSON
// (a killed scanner can tear its last record). It always drains r so the child
// process never blocks on a full pipe, even after onLine fails.
func streamLines(r io.Reader, maxLine int, onLine func([]byte) error) (dropped int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var buf []byte
	oversized := false
	for {
		chunk, readErr := br.ReadSlice('\n')
		if !oversized {
			if len(buf)+len(chunk) > maxLine {
				oversized, buf = true, buf[:0]
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		line := bytes.TrimSpace(buf)
		if readErr == nil {
			if oversized {
				dropped++
			} else if len(line) > 0 && err == nil {
				err = onLine(line)
			}
			buf, oversized = buf[:0], false
			continue
		}
		if !oversized && len(line) > 0 && json.Valid(line) && err == nil {
			err = onLine(line)
		}
		if !errors.Is(readErr, io.EOF) && err == nil {
			err = readErr
		}
		return dropped, err
	}
}

// Three processes saturate the per-root gateway budget; more only adds template
// load cost and memory.
func detectionWorkers(sc Scan) int { return min(scanConcurrency(sc, 3), max(1, sc.Rate)) }

// nucleiParallelism splits the scan budget so aggregate requests/s across all
// nuclei processes is <= Scan.Rate and aggregate in-flight work is <= Scan.Concurrency.
func nucleiParallelism(sc Scan, workers, templates int) (rate, templateConc, hostConc int) {
	workers = max(1, workers)
	rate = max(1, sc.Rate/workers)
	perWorker := max(1, scanConcurrency(sc, 10)/workers)
	templateConc = max(1, min(templates, 2, perWorker))
	hostConc = max(1, perWorker/templateConc)
	return rate, templateConc, hostConc
}

// One process per worker amortizes template parsing/signature checks; the cap
// bounds the coverage lost if a single batch is killed.
func splitDetectionBatches(urls []string, workers int) [][]string {
	if len(urls) == 0 {
		return nil
	}
	size := min(50, max(5, (len(urls)+max(1, workers)-1)/max(1, workers)))
	var out [][]string
	for i := 0; i < len(urls); i += size {
		out = append(out, urls[i:min(i+size, len(urls))])
	}
	return out
}
