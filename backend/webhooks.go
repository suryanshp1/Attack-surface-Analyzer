package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return errors.New("webhooks require a public HTTPS URL on port 443 without user credentials or fragments")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicIP(ip) {
		return errors.New("webhook destination must be public")
	}
	return nil
}

// Pin each connection to the addresses checked here, including on subsequent
// deliveries. A URL validation lookup alone would allow DNS rebinding.
func dialWebhook(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errors.New("invalid webhook address")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("webhook DNS lookup failed")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, errors.New("webhook destination must be public")
		}
	}
	for _, ip := range ips {
		conn, dialErr := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, err
}

func newWebhookClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: dialWebhook, TLSHandshakeTimeout: 3 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second, DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func publicWebhooks(webhooks []NotificationWebhook) []NotificationWebhook {
	out := make([]NotificationWebhook, 0, len(webhooks))
	for _, wh := range webhooks {
		u, err := url.Parse(wh.URL)
		wh.URL = "[REDACTED]"
		if err == nil && u.Hostname() != "" {
			wh.URL = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/[REDACTED]"}).String()
		}
		out = append(out, wh)
	}
	return out
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	var p struct{ ID, URL string }
	if !decode(w, r, &p) {
		return
	}
	s.mu.Lock()
	actor, authorized := s.actorLocked(r)
	var wh NotificationWebhook
	if authorized && actor.Role == "owner" {
		for _, saved := range s.state.Webhooks {
			if saved.ID == p.ID {
				wh = saved
				break
			}
		}
	}
	s.mu.Unlock()
	if !authorized {
		fail(w, 401, "Unauthorized")
		return
	}
	if actor.Role != "owner" {
		fail(w, 403, "Owner access required")
		return
	}
	if p.ID != "" && wh.ID == "" {
		fail(w, 404, "Webhook not found")
		return
	}
	if p.ID == "" {
		wh = NotificationWebhook{URL: p.URL, WebhookType: "generic"}
	}
	// Explicit test requests deliver even for disabled saved hooks.
	wh.Enabled = true
	if err := validateWebhookURL(wh.URL); err != nil {
		fail(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	payload := WebhookPayload{Event: "test", Title: "Surfacer Webhook Test", Detail: "This is a test notification from Surfacer Attack Surface Management.", Timestamp: now()}
	if err := DispatchWebhook(ctx, nil, wh, payload); err != nil {
		fail(w, 502, "Webhook delivery failed")
		return
	}
	respond(w, 200, map[string]string{"status": "delivered"})
}

type WebhookPayload struct {
	Event     string         `json:"event"`
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data,omitempty"`
}

func formatSlackPayload(p WebhookPayload) map[string]any {
	color := "#3b82f6"
	switch p.Event {
	case "takeover", "high_finding":
		color = "#ef4444"
	case "port_change":
		color = "#f59e0b"
	case "new_asset":
		color = "#10b981"
	}
	return map[string]any{
		"text": fmt.Sprintf("Surfacer: %s - %s", p.Title, p.Detail),
		"attachments": []map[string]any{
			{
				"color": color,
				"title": p.Title,
				"text":  p.Detail,
				"fields": []map[string]any{
					{"title": "Event", "value": p.Event, "short": true},
					{"title": "Timestamp", "value": p.Timestamp, "short": true},
				},
				"footer": "Surfacer Attack Surface Management",
			},
		},
	}
}

func formatDiscordPayload(p WebhookPayload) map[string]any {
	color := 3900150 // blue
	switch p.Event {
	case "takeover", "high_finding":
		color = 15680324 // red
	case "port_change":
		color = 16101131 // orange
	case "new_asset":
		color = 1096065 // green
	}
	return map[string]any{
		"content": fmt.Sprintf("**Surfacer Alert: %s**\n%s", p.Title, p.Detail),
		"embeds": []map[string]any{
			{
				"title":       p.Title,
				"description": p.Detail,
				"color":       color,
				"fields": []map[string]any{
					{"name": "Event", "value": p.Event, "inline": true},
					{"name": "Timestamp", "value": p.Timestamp, "inline": true},
				},
				"footer": map[string]any{"text": "Surfacer Attack Surface Management"},
			},
		},
	}
}

// DispatchWebhook sends an event payload to a single configured webhook if enabled and matching triggers.
func DispatchWebhook(ctx context.Context, client *http.Client, wh NotificationWebhook, payload WebhookPayload) error {
	if !wh.Enabled {
		return nil
	}

	// Filter based on trigger preferences
	switch payload.Event {
	case "new_asset":
		if !wh.NotifyOnNewAssets {
			return nil
		}
	case "port_change":
		if !wh.NotifyOnNewPorts {
			return nil
		}
	case "high_finding":
		if !wh.NotifyOnHighFindings {
			return nil
		}
	case "takeover":
		if !wh.NotifyOnTakeovers {
			return nil
		}
	case "test":
		// Test events always deliver
	default:
		return nil
	}

	if client == nil {
		client = newWebhookClient()
	}
	if err := validateWebhookURL(wh.URL); err != nil {
		return err
	}

	var body any
	switch strings.ToLower(wh.WebhookType) {
	case "slack":
		body = formatSlackPayload(payload)
	case "discord":
		body = formatDiscordPayload(payload)
	default:
		body = payload
	}

	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", wh.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Surfacer-Notifier/1.0")

	res, err := client.Do(req)
	if err != nil {
		// net/url errors include the full credential-bearing URL.
		return errors.New("webhook connection failed")
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		return fmt.Errorf("webhook responded with HTTP %d", res.StatusCode)
	}
	return nil
}

// The caller snapshots webhooks while holding the workspace lock. Never acquire it again here.
func (s *Server) dispatchWebhooksAsync(kind, title, detail, stamp string, webhooks []NotificationWebhook) {
	var eventType string
	switch {
	case kind == "takeover":
		eventType = "takeover"
	case kind == "asset" && strings.Contains(strings.ToLower(title), "new"):
		eventType = "new_asset"
	case kind == "port":
		eventType = "port_change"
	case kind == "finding" && (strings.Contains(strings.ToLower(title), "critical") || strings.Contains(strings.ToLower(title), "high")):
		eventType = "high_finding"
	default:
		return
	}

	if len(webhooks) == 0 {
		return
	}

	payload := WebhookPayload{
		Event:     eventType,
		Title:     title,
		Detail:    detail,
		Timestamp: stamp,
	}

	client := newWebhookClient()
	for _, wh := range webhooks {
		if !wh.Enabled {
			continue
		}
		targetWebhook := wh
		go func() {
			defer func() { _ = recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			_ = DispatchWebhook(ctx, client, targetWebhook, payload)
		}()
	}
}
