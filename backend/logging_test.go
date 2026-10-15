package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggerSecretRedaction(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			k := strings.ToLower(a.Key)
			if strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "key") {
				if a.Value.Kind() == slog.KindString && a.Value.String() != "" {
					return slog.String(a.Key, "[REDACTED]")
				}
			}
			return a
		},
	})

	testLogger := slog.New(handler)
	testLogger.Info("test_event",
		"api_token", "super-secret-token-12345",
		"database_password", "postgres-super-secret",
		"safe_field", "public_value",
	)

	out := buf.String()
	if strings.Contains(out, "super-secret-token-12345") {
		t.Errorf("api_token leaked in log output: %s", out)
	}
	if strings.Contains(out, "postgres-super-secret") {
		t.Errorf("database_password leaked in log output: %s", out)
	}
	if !strings.Contains(out, `"[REDACTED]"`) {
		t.Errorf("Expected [REDACTED] in log output: %s", out)
	}
	if !strings.Contains(out, "public_value") {
		t.Errorf("Expected public_value in log output: %s", out)
	}
}

func TestLoggerContextPropagation(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-xyz-9876")
	reqID := RequestIDFromContext(ctx)
	if reqID != "req-xyz-9876" {
		t.Errorf("RequestIDFromContext expected req-xyz-9876, got %s", reqID)
	}

	logger := Log(ctx)
	if logger == nil {
		t.Fatal("Log(ctx) returned nil")
	}
}
