package main

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// idSegment matches alphanumeric IDs, hex strings, or UUIDs in URL paths
	idSegment = regexp.MustCompile(`^[a-f0-9]{16,64}$|^[a-zA-Z0-9_\-]+_[a-zA-Z0-9_\-]+$`)
)

// Telemetry captures in-memory performance and reliability metrics.
// Cardinality is strictly bounded to prevent memory exhaustion or metric explosion.
type Telemetry struct {
	mu sync.RWMutex

	// Inflight HTTP requests
	inflightRequests int64

	// HTTP request counts keyed by "method:path:status_class"
	httpRequests map[string]*uint64

	// Latency trackers in milliseconds: sum and count per "method:path"
	latencySumMs map[string]*uint64
	latencyCount map[string]*uint64

	// Security and Gateway counters
	gatewayEgressTotal  uint64
	gatewayBlockedTotal uint64
	rateLimitStrikes    uint64
	checkpointWrites    uint64
	checkpointFailures  uint64
	checkpointMillis    uint64
	stageTimeouts       uint64

	// Scan engine metrics
	stageDurationsSec map[string]*uint64 // stage_name -> cumulative seconds
	stageExecutions   map[string]*uint64 // stage_name -> count
}

var GlobalTelemetry = NewTelemetry()

func NewTelemetry() *Telemetry {
	return &Telemetry{
		httpRequests:      make(map[string]*uint64),
		latencySumMs:      make(map[string]*uint64),
		latencyCount:      make(map[string]*uint64),
		stageDurationsSec: make(map[string]*uint64),
		stageExecutions:   make(map[string]*uint64),
	}
}

// NormalizeRoute collapses dynamic URL path segments to prevent unbounded metric cardinality.
func NormalizeRoute(rawPath string) string {
	clean := strings.Trim(strings.TrimPrefix(rawPath, "/api/"), "/")
	if clean == "" {
		return "/"
	}
	parts := strings.Split(clean, "/")
	for i, part := range parts {
		if idSegment.MatchString(part) || len(part) >= 16 {
			parts[i] = ":id"
		}
	}
	return "/" + strings.Join(parts, "/")
}

// RecordRequest observes an HTTP request completion.
func (t *Telemetry) RecordRequest(method, route string, statusCode int, duration time.Duration) {
	normRoute := NormalizeRoute(route)
	statusClass := strconv.Itoa(statusCode/100) + "xx"
	key := method + ":" + normRoute + ":" + statusClass

	t.mu.RLock()
	counter, exists := t.httpRequests[key]
	t.mu.RUnlock()

	if !exists {
		t.mu.Lock()
		counter, exists = t.httpRequests[key]
		if !exists {
			var val uint64
			counter = &val
			t.httpRequests[key] = counter
		}
		t.mu.Unlock()
	}
	atomic.AddUint64(counter, 1)

	// Record duration
	latKey := method + ":" + normRoute
	durMs := uint64(duration.Milliseconds())

	t.mu.RLock()
	sumPtr := t.latencySumMs[latKey]
	cntPtr := t.latencyCount[latKey]
	t.mu.RUnlock()

	if sumPtr == nil || cntPtr == nil {
		t.mu.Lock()
		if t.latencySumMs[latKey] == nil {
			var s, c uint64
			t.latencySumMs[latKey] = &s
			t.latencyCount[latKey] = &c
		}
		sumPtr = t.latencySumMs[latKey]
		cntPtr = t.latencyCount[latKey]
		t.mu.Unlock()
	}
	atomic.AddUint64(sumPtr, durMs)
	atomic.AddUint64(cntPtr, 1)
}

func (t *Telemetry) IncInflight() {
	atomic.AddInt64(&t.inflightRequests, 1)
}

func (t *Telemetry) DecInflight() {
	atomic.AddInt64(&t.inflightRequests, -1)
}

func (t *Telemetry) RecordBlockedEgress() {
	atomic.AddUint64(&t.gatewayBlockedTotal, 1)
}

func (t *Telemetry) RecordEgress() {
	atomic.AddUint64(&t.gatewayEgressTotal, 1)
}

func (t *Telemetry) RecordRateLimitStrike() {
	atomic.AddUint64(&t.rateLimitStrikes, 1)
}

func (t *Telemetry) RecordCheckpoint(duration time.Duration, failed bool) {
	atomic.AddUint64(&t.checkpointWrites, 1)
	atomic.AddUint64(&t.checkpointMillis, uint64(max(0, duration.Milliseconds())))
	if failed {
		atomic.AddUint64(&t.checkpointFailures, 1)
	}
}

func (t *Telemetry) RecordStageTimeout() { atomic.AddUint64(&t.stageTimeouts, 1) }

func (t *Telemetry) RecordStageDuration(stageName string, duration time.Duration) {
	secs := uint64(duration.Seconds())
	if secs == 0 && duration > 0 {
		secs = 1
	}

	t.mu.RLock()
	durPtr := t.stageDurationsSec[stageName]
	cntPtr := t.stageExecutions[stageName]
	t.mu.RUnlock()

	if durPtr == nil || cntPtr == nil {
		t.mu.Lock()
		if t.stageDurationsSec[stageName] == nil {
			var d, c uint64
			t.stageDurationsSec[stageName] = &d
			t.stageExecutions[stageName] = &c
		}
		durPtr = t.stageDurationsSec[stageName]
		cntPtr = t.stageExecutions[stageName]
		t.mu.Unlock()
	}
	atomic.AddUint64(durPtr, secs)
	atomic.AddUint64(cntPtr, 1)
}

// WritePrometheus writes current operational and runtime metrics to the writer.
func (t *Telemetry) WritePrometheus(w io.Writer) {
	fmt.Fprintf(w, "# TYPE surfacer_http_requests_inflight gauge\n")
	fmt.Fprintf(w, "surfacer_http_requests_inflight %d\n", atomic.LoadInt64(&t.inflightRequests))

	fmt.Fprintf(w, "# TYPE surfacer_gateway_egress_total counter\n")
	fmt.Fprintf(w, "surfacer_gateway_egress_total %d\n", atomic.LoadUint64(&t.gatewayEgressTotal))

	fmt.Fprintf(w, "# TYPE surfacer_gateway_blocked_egress_total counter\n")
	fmt.Fprintf(w, "surfacer_gateway_blocked_egress_total %d\n", atomic.LoadUint64(&t.gatewayBlockedTotal))

	fmt.Fprintf(w, "# TYPE surfacer_gateway_ratelimit_strikes_total counter\n")
	fmt.Fprintf(w, "surfacer_gateway_ratelimit_strikes_total %d\n", atomic.LoadUint64(&t.rateLimitStrikes))

	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.httpRequests) > 0 {
		fmt.Fprintf(w, "# TYPE surfacer_http_requests_total counter\n")
		for key, countPtr := range t.httpRequests {
			parts := strings.SplitN(key, ":", 3)
			if len(parts) == 3 {
				fmt.Fprintf(w, "surfacer_http_requests_total{method=%s,path=%s,status_class=%s} %d\n",
					strconv.Quote(parts[0]), strconv.Quote(parts[1]), strconv.Quote(parts[2]), atomic.LoadUint64(countPtr))
			}
		}
	}

	if len(t.latencyCount) > 0 {
		fmt.Fprintf(w, "# TYPE surfacer_http_request_duration_seconds summary\n")
		for key, cntPtr := range t.latencyCount {
			sumPtr := t.latencySumMs[key]
			parts := strings.SplitN(key, ":", 2)
			if len(parts) == 2 && sumPtr != nil {
				cnt := atomic.LoadUint64(cntPtr)
				sumSec := float64(atomic.LoadUint64(sumPtr)) / 1000.0
				fmt.Fprintf(w, "surfacer_http_request_duration_seconds_sum{method=%s,path=%s} %.3f\n",
					strconv.Quote(parts[0]), strconv.Quote(parts[1]), sumSec)
				fmt.Fprintf(w, "surfacer_http_request_duration_seconds_count{method=%s,path=%s} %d\n",
					strconv.Quote(parts[0]), strconv.Quote(parts[1]), cnt)
			}
		}
	}

	if len(t.stageDurationsSec) > 0 {
		fmt.Fprintf(w, "# TYPE surfacer_scan_stage_duration_seconds summary\n")
		for stage, durPtr := range t.stageDurationsSec {
			cntPtr := t.stageExecutions[stage]
			if cntPtr != nil {
				fmt.Fprintf(w, "surfacer_scan_stage_duration_seconds_sum{stage=%s} %d\n",
					strconv.Quote(stage), atomic.LoadUint64(durPtr))
				fmt.Fprintf(w, "surfacer_scan_stage_duration_seconds_count{stage=%s} %d\n",
					strconv.Quote(stage), atomic.LoadUint64(cntPtr))
			}
		}
	}

	fmt.Fprintf(w, "# TYPE surfacer_checkpoint_writes_total counter\nsurfacer_checkpoint_writes_total %d\n", atomic.LoadUint64(&t.checkpointWrites))
	fmt.Fprintf(w, "# TYPE surfacer_checkpoint_failures_total counter\nsurfacer_checkpoint_failures_total %d\n", atomic.LoadUint64(&t.checkpointFailures))
	fmt.Fprintf(w, "# TYPE surfacer_checkpoint_duration_seconds summary\nsurfacer_checkpoint_duration_seconds_sum %.3f\nsurfacer_checkpoint_duration_seconds_count %d\n", float64(atomic.LoadUint64(&t.checkpointMillis))/1000, atomic.LoadUint64(&t.checkpointWrites))
	fmt.Fprintf(w, "# TYPE surfacer_scan_stage_timeouts_total counter\nsurfacer_scan_stage_timeouts_total %d\n", atomic.LoadUint64(&t.stageTimeouts))

	// Runtime metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(w, "# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# TYPE go_memstats_alloc_bytes gauge\ngo_memstats_alloc_bytes %d\n", m.Alloc)
	fmt.Fprintf(w, "# TYPE go_memstats_sys_bytes gauge\ngo_memstats_sys_bytes %d\n", m.Sys)
	fmt.Fprintf(w, "# TYPE go_memstats_gc_sys_bytes gauge\ngo_memstats_gc_sys_bytes %d\n", m.GCSys)
}
