package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func watchFixture(t *testing.T) *Server {
	t.Helper()
	t.Setenv("WORKER_TOKEN", "fixture-worker")
	s := testServer(t)
	s.state = emptyState()
	s.state.Targets = []Target{{ID: "target", Domain: "owned.example", Status: "verified"}}
	s.state.Scans = []Scan{{ID: "scan", TargetID: "target", Domain: "owned.example", Status: "running", Worker: "fixture", Lease: "lease", LeaseUntil: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Stages: []Stage{{Name: "Detection", Status: "running"}}}}
	return s
}

func workerRequest(s *Server, path, body string) <-chan int {
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer fixture-worker")
		w := httptest.NewRecorder()
		s.handle(w, r)
		done <- w.Code
	}()
	return done
}

func TestScanWatchDeliversCancellationImmediately(t *testing.T) {
	s := watchFixture(t)
	const body = `{"worker":"fixture","scanId":"scan","lease":"lease"}`
	watch := workerRequest(s, "/internal/watch", body)
	select {
	case code := <-watch:
		t.Fatal("watch returned while scan was active", code)
	case <-time.After(150 * time.Millisecond):
	}
	// Unrelated persisted changes (heartbeats) wake the watcher but must not end it.
	if code := <-workerRequest(s, "/internal/heartbeat", body); code != 200 {
		t.Fatal("heartbeat failed", code)
	}
	select {
	case code := <-watch:
		t.Fatal("heartbeat ended watch on an active scan", code)
	case <-time.After(100 * time.Millisecond):
	}
	if w := request(s, "POST", "/api/scans/scan/cancel", `{}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	select {
	case code := <-watch:
		if code != 409 {
			t.Fatal("cancellation delivered with wrong status", code)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation not pushed to watching worker")
	}
	// A canceled lease is rejected without waiting.
	select {
	case code := <-workerRequest(s, "/internal/watch", body):
		if code != 409 {
			t.Fatal("canceled lease accepted", code)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("canceled lease watch blocked")
	}
}

func TestScanWatchHonorsKillSwitch(t *testing.T) {
	s := watchFixture(t)
	watch := workerRequest(s, "/internal/watch", `{"worker":"fixture","scanId":"scan","lease":"lease"}`)
	time.Sleep(50 * time.Millisecond)
	if w := request(s, "PATCH", "/api/settings", `{"name":"Fixture","rate":5,"concurrency":2,"retention":30,"paused":true}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	select {
	case code := <-watch:
		if code != 409 {
			t.Fatal("kill switch delivered with wrong status", code)
		}
	case <-time.After(time.Second):
		t.Fatal("kill switch not pushed to watching worker")
	}
}

func TestWorkerCancellationWatchStopsOnlyOnLeaseRejection(t *testing.T) {
	var status atomic.Int32
	status.Store(404) // Older API without the watch endpoint.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "fixture", int(status.Load()))
	}))
	defer srv.Close()
	w := &Worker{API: srv.URL, client: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stopped atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.watchCancellation(ctx, Scan{ID: "scan", Lease: "lease"}, 10*time.Millisecond, func() { stopped.Store(true) })
	}()
	time.Sleep(60 * time.Millisecond)
	if stopped.Load() {
		t.Fatal("unsupported watch endpoint canceled the scan")
	}
	status.Store(409)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lease rejection did not stop the scan")
	}
	if !stopped.Load() || calls.Load() < 2 {
		t.Fatal("watch did not stop scan after rejection", stopped.Load(), calls.Load())
	}
}
