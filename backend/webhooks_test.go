package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookDispatchSlack(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NotificationWebhook{
		ID:                "wh-1",
		URL:               srv.URL,
		WebhookType:       "slack",
		Enabled:           true,
		NotifyOnNewAssets: true,
	}

	payload := WebhookPayload{
		Event:     "new_asset",
		Title:     "New asset discovered",
		Detail:    "api.example.com",
		Timestamp: now(),
	}

	err := DispatchWebhook(context.Background(), srv.Client(), wh, payload)
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(receivedBody, &data); err != nil {
		t.Fatalf("invalid json received: %v", err)
	}

	if !strings.Contains(data["text"].(string), "New asset discovered") {
		t.Fatalf("unexpected slack text: %v", data["text"])
	}
}

func TestWebhookDispatchDiscord(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NotificationWebhook{
		ID:                "wh-2",
		URL:               srv.URL,
		WebhookType:       "discord",
		Enabled:           true,
		NotifyOnTakeovers: true,
	}

	payload := WebhookPayload{
		Event:     "takeover",
		Title:     "Subdomain takeover candidate detected",
		Detail:    "sub.example.com pointing to unclaimed AWS S3",
		Timestamp: now(),
	}

	err := DispatchWebhook(context.Background(), srv.Client(), wh, payload)
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(receivedBody, &data); err != nil {
		t.Fatalf("invalid json received: %v", err)
	}

	if !strings.Contains(data["content"].(string), "Subdomain takeover candidate") {
		t.Fatalf("unexpected discord content: %v", data["content"])
	}
}

func TestWebhookFilterTrigger(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NotificationWebhook{
		ID:                "wh-3",
		URL:               srv.URL,
		WebhookType:       "generic",
		Enabled:           true,
		NotifyOnNewAssets: false, // disabled for new_assets
	}

	payload := WebhookPayload{
		Event:     "new_asset",
		Title:     "New asset discovered",
		Detail:    "test.example.com",
		Timestamp: now(),
	}

	err := DispatchWebhook(context.Background(), srv.Client(), wh, payload)
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	if called {
		t.Fatal("webhook was called despite trigger being disabled")
	}
}
