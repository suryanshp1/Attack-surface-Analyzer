package main

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTelemetryBoundedCardinality(t *testing.T) {
	paths := []struct {
		input    string
		expected string
	}{
		{"/api/targets", "/targets"},
		{"/api/targets/t_1234567890abcdef", "/targets/:id"},
		{"/api/scans/4f8b2c1e9a3d4e5f6a7b8c9d0e1f2a3b", "/scans/:id"},
		{"/api/scans/4f8b2c1e9a3d4e5f6a7b8c9d0e1f2a3b/stages/3", "/scans/:id/stages/3"},
		{"/api/state", "/state"},
		{"/api/metrics", "/metrics"},
	}

	for _, p := range paths {
		got := NormalizeRoute(p.input)
		if got != p.expected {
			t.Errorf("NormalizeRoute(%q) = %q, expected %q", p.input, got, p.expected)
		}
	}
}

func TestTelemetryPrometheusExposition(t *testing.T) {
	tel := NewTelemetry()
	tel.IncInflight()
	tel.RecordRequest("GET", "/api/targets", 200, 45*time.Millisecond)
	tel.RecordRequest("POST", "/api/targets", 400, 10*time.Millisecond)
	tel.RecordBlockedEgress()
	tel.RecordEgress()
	tel.RecordRateLimitStrike()
	tel.RecordStageDuration("Discovery", 3*time.Second)

	var buf bytes.Buffer
	tel.WritePrometheus(&buf)
	out := buf.String()

	requiredMetrics := []string{
		"surfacer_http_requests_inflight 1",
		"surfacer_gateway_egress_total 1",
		"surfacer_gateway_blocked_egress_total 1",
		"surfacer_gateway_ratelimit_strikes_total 1",
		`surfacer_http_requests_total{method="GET",path="/targets",status_class="2xx"} 1`,
		`surfacer_http_requests_total{method="POST",path="/targets",status_class="4xx"} 1`,
		`surfacer_http_request_duration_seconds_count{method="GET",path="/targets"} 1`,
		`surfacer_scan_stage_duration_seconds_count{stage="Discovery"} 1`,
		"go_goroutines",
		"go_memstats_alloc_bytes",
	}

	for _, req := range requiredMetrics {
		if !strings.Contains(out, req) {
			t.Errorf("Prometheus output missing %q:\n%s", req, out)
		}
	}

	tel.DecInflight()
	buf.Reset()
	tel.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), "surfacer_http_requests_inflight 0") {
		t.Error("inflight requests counter did not decrement to 0")
	}
}

func TestTelemetryConcurrency(t *testing.T) {
	tel := NewTelemetry()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tel.IncInflight()
				tel.RecordRequest("GET", "/api/state", 200, time.Millisecond)
				tel.RecordEgress()
				tel.RecordBlockedEgress()
				tel.RecordStageDuration("Port discovery", 50*time.Millisecond)
				tel.DecInflight()
			}
		}(i)
	}

	wg.Wait()

	var buf bytes.Buffer
	tel.WritePrometheus(&buf)
	if !strings.Contains(buf.String(), `surfacer_http_requests_total{method="GET",path="/state",status_class="2xx"} 2000`) {
		t.Errorf("Concurrency test failed, expected 2000 requests, got:\n%s", buf.String())
	}
}
