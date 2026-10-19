package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Variants keep the scanner identifiable rather than impersonating browsers.
func scannerAgent(scan, stage string) string {
	variants := []string{"Surfacer/1.0 (external-surface-monitor; profile=standard)", "Surfacer/1.0 (external-surface-monitor; profile=inventory)", "Surfacer/1.0 (external-surface-monitor; profile=assessment)"}
	hash := sha256.Sum256([]byte(scan + ":" + stage))
	return variants[int(hash[0])%len(variants)]
}
func retryDelay(header string, at time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds >= 0 {
		if seconds > 86400*365 {
			return 365 * 24 * time.Hour
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(header); err == nil && date.After(at) {
		return date.Sub(at)
	}
	return 0
}

type trafficSlot struct {
	next, cooldown  time.Time
	active, strikes int
	touched         time.Time
}
type trafficGovernor struct {
	mu          sync.Mutex
	slots       map[string]*trafficSlot
	interval    time.Duration
	concurrency int
	sequence    uint64
}

type trafficPolicy struct {
	interval time.Duration
	limit    int
}

// Signed permits carry the scan's configured budget; legacy permits keep the
// conservative 2 req/s, 2-concurrent default.
func permitTrafficPolicy(p Permit) trafficPolicy {
	if p.Rate <= 0 {
		return trafficPolicy{}
	}
	return trafficPolicy{interval: time.Second / time.Duration(min(max(p.Rate, 1), 30)), limit: min(max(p.Concurrency, 1), 10)}
}

func (g *trafficGovernor) acquire(ctx context.Context, key string) (func(), error) {
	return g.acquirePolicy(ctx, key, trafficPolicy{interval: g.interval, limit: g.concurrency})
}

func (g *trafficGovernor) acquirePolicy(ctx context.Context, key string, p trafficPolicy) (func(), error) {
	for {
		g.mu.Lock()
		if g.slots == nil {
			g.slots = map[string]*trafficSlot{}
		}
		now := time.Now()
		if len(g.slots) > 1024 {
			for k, s := range g.slots {
				if s.active == 0 && now.After(s.cooldown) && now.Sub(s.touched) > time.Hour {
					delete(g.slots, k)
				}
			}
		}
		slot := g.slots[key]
		if slot == nil {
			slot = &trafficSlot{}
			g.slots[key] = slot
		}
		interval := p.interval
		if interval <= 0 {
			interval = g.interval
		}
		if interval <= 0 {
			interval = 500 * time.Millisecond
		}
		limit := p.limit
		if limit <= 0 {
			limit = g.concurrency
		}
		if limit <= 0 {
			limit = 2
		}
		ready := slot.next
		if slot.cooldown.After(ready) {
			ready = slot.cooldown
		}
		if slot.active < limit && !now.Before(ready) {
			slot.active++
			slot.touched = now
			// Small added jitter spreads arrivals without raising the configured rate.
			g.sequence++
			slot.next = now.Add(interval + time.Duration(g.sequence%11)*interval/100)
			g.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { g.mu.Lock(); slot.active--; g.mu.Unlock() }) }, nil
		}
		delay := time.Until(ready)
		if delay < 5*time.Millisecond {
			delay = 5 * time.Millisecond
		}
		if delay > min(interval, time.Second) {
			delay = min(interval, time.Second)
		}
		g.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
func (g *trafficGovernor) observe(key string, status int, header string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.slots == nil {
		g.slots = map[string]*trafficSlot{}
	}
	slot := g.slots[key]
	if slot == nil {
		slot = &trafficSlot{}
		g.slots[key] = slot
	}
	now := time.Now()
	slot.touched = now
	if status == 429 || status == 503 || (status == 403 && retryDelay(header, now) > 0) {
		GlobalTelemetry.RecordRateLimitStrike()
		slot.strikes = min(slot.strikes+1, 7)
		delay := time.Duration(1<<slot.strikes) * time.Second
		if explicit := retryDelay(header, now); explicit > delay {
			delay = explicit
		}
		until := now.Add(delay)
		if until.After(slot.cooldown) {
			slot.cooldown = until
		}
	} else if status >= 200 && status < 400 {
		slot.strikes = 0
	}
}

// HTTPS response headers are visible to the worker, not the CONNECT gateway.
func reportCooldown(ctx context.Context, proxy, host string, status int, retryAfter string) {
	p, err := url.Parse(proxy)
	if err != nil || p.User == nil {
		return
	}
	username := p.User.Username()
	password, _ := p.User.Password()
	p.User = nil
	p.Path = "/internal/cooldown"
	p.RawQuery = ""
	body, _ := json.Marshal(map[string]any{"host": host, "status": status, "retryAfter": retryAfter})
	req, err := http.NewRequestWithContext(ctx, "POST", p.String(), bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err == nil {
		response.Body.Close()
	}
}
