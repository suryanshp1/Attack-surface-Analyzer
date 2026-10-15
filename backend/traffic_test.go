package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRetryAfterSecondsAndDate(t *testing.T) {
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"120", 2 * time.Minute}, {"Wed, 14 Oct 2026 00:01:00 GMT", time.Minute}, {"garbage", 0}, {"-1", 0}, {"Tue, 13 Oct 2026 23:59:00 GMT", 0}} {
		if got := retryDelay(tc.value, at); got != tc.want {
			t.Errorf("%s: %s", tc.value, got)
		}
	}
}
func TestCooldownCannotBeShortenedBySuccess(t *testing.T) {
	g := trafficGovernor{}
	g.observe("domain", 429, "120")
	until := g.slots["domain"].cooldown
	if time.Until(until) < 119*time.Second {
		t.Fatal("Retry-After ignored")
	}
	g.observe("domain", 200, "")
	if g.slots["domain"].cooldown != until {
		t.Fatal("concurrent success cleared cooldown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.acquire(ctx, "domain"); err == nil {
		t.Fatal("request admitted during cooldown")
	}
}
func TestTrafficConcurrencyAndCancellation(t *testing.T) {
	g := trafficGovernor{interval: time.Nanosecond, concurrency: 1}
	release, err := g.acquire(context.Background(), "domain")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.acquire(ctx, "domain"); err == nil {
		t.Fatal("concurrency cap bypassed")
	}
	release()
	release()
	if g.slots["domain"].active != 0 {
		t.Fatal("release is not idempotent")
	}
}
func TestScannerAgentsRemainIdentifiable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		agent := scannerAgent(strings.Repeat("x", i), "http")
		if !strings.HasPrefix(agent, "Surfacer/1.0") {
			t.Fatal("scanner impersonates browser")
		}
		seen[agent] = true
	}
	if len(seen) < 2 {
		t.Fatal("agent variants did not rotate")
	}
}
