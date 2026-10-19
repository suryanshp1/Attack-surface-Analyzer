package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

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
		client = &http.Client{Timeout: 5 * time.Second}
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
		return err
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

	client := &http.Client{Timeout: 5 * time.Second}
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
