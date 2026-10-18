package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCommitStageRetriesTransientAPIErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "busy", 503)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	w := &Worker{API: srv.URL, client: srv.Client()}
	if err := w.commitStage(context.Background(), map[string]any{}); err != nil || calls.Load() != 3 {
		t.Fatal("transient failure not retried", err, calls.Load())
	}
}

func TestCommitStageDoesNotRetryLeaseRejection(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "lease", 409)
	}))
	defer srv.Close()
	w := &Worker{API: srv.URL, client: srv.Client()}
	if err := w.commitStage(context.Background(), map[string]any{}); err == nil || calls.Load() != 1 {
		t.Fatal("stale lease retried", err, calls.Load())
	}
}

func TestHeartbeatShouldStop(t *testing.T) {
	now := time.Now()
	if heartbeatShouldStop(&workerAPIError{status: 503}, now.Add(-5*time.Second), now) {
		t.Fatal("single transient heartbeat failure canceled scan")
	}
	if !heartbeatShouldStop(&workerAPIError{status: 409}, now, now) {
		t.Fatal("lease rejection ignored")
	}
	if !heartbeatShouldStop(errors.New("dial"), now.Add(-21*time.Second), now) {
		t.Fatal("heartbeat outage past safety window ignored")
	}
}
