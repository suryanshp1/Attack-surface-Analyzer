package main

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
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
func TestForbiddenDoesNotTriggerCooldown(t *testing.T) {
	g := trafficGovernor{}
	g.observe("domain", 403, "")
	slot := g.slots["domain"]
	if slot != nil && !slot.cooldown.IsZero() && time.Until(slot.cooldown) > 0 {
		t.Fatalf("HTTP 403 triggered unexpected cooldown until %s", slot.cooldown)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	release, err := g.acquire(ctx, "domain")
	if err != nil {
		t.Fatalf("request blocked after 403 response: %v", err)
	}
	release()
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

func TestTrafficPolicyHonorsScanRate(t *testing.T) {
	var g trafficGovernor
	count := func(p trafficPolicy) int {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		n := 0
		for {
			release, err := g.acquirePolicy(ctx, fmt.Sprint(p), p)
			if err != nil {
				return n
			}
			release()
			n++
		}
	}
	if n := count(permitTrafficPolicy(Permit{Rate: 20, Concurrency: 5})); n < 14 || n > 21 {
		t.Fatal("scan rate not honored", n)
	}
	if n := count(permitTrafficPolicy(Permit{})); n > 3 {
		t.Fatal("legacy permit pacing loosened", n)
	}
	if p := permitTrafficPolicy(Permit{Rate: 500, Concurrency: 99}); p.interval < time.Second/30 || p.limit > 10 {
		t.Fatal("permit policy not clamped", p)
	}
}

func TestGatewayAuthorizeCacheBoundsRevocationDelay(t *testing.T) {
	var calls atomic.Int32
	var allowed atomic.Bool
	allowed.Store(true)
	g := &Gateway{
		authorize: func(ctx context.Context, permit string) bool {
			calls.Add(1)
			return allowed.Load()
		},
	}
	for i := 0; i < 10; i++ {
		if !g.activeCached(context.Background(), "permit-1") {
			t.Fatal("expected cached permit to be active")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
	allowed.Store(false)
	// Still true within cache
	if !g.activeCached(context.Background(), "permit-1") {
		t.Fatal("expected permit to remain active within 2s TTL")
	}
	// Expire cache
	g.authMu.Lock()
	g.authUntil["permit-1"] = time.Now().Add(-time.Second)
	g.authMu.Unlock()
	// Now should call authorize and get false
	if g.activeCached(context.Background(), "permit-1") {
		t.Fatal("expected permit to be rejected after cache expiry")
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 calls, got %d", calls.Load())
	}
}
