package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
)

type contextKey string

const requestIDContextKey contextKey = "request_id"

var (
	loggerOnce sync.Once
	rootLogger *slog.Logger
)

// InitLogger configures the application-wide structured logger.
// It supports "json" and "text" formats and respects LOG_LEVEL (DEBUG, INFO, WARN, ERROR).
func InitLogger() *slog.Logger {
	loggerOnce.Do(func() {
		format := strings.ToLower(os.Getenv("LOG_FORMAT"))
		levelStr := strings.ToUpper(os.Getenv("LOG_LEVEL"))

		var level slog.Level
		switch levelStr {
		case "DEBUG":
			level = slog.LevelDebug
		case "WARN":
			level = slog.LevelWarn
		case "ERROR":
			level = slog.LevelError
		default:
			level = slog.LevelInfo
		}

		opts := &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Strip or mask sensitive keys if ever accidentally passed
				k := strings.ToLower(a.Key)
				if strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "key") {
					if a.Value.Kind() == slog.KindString && a.Value.String() != "" {
						return slog.String(a.Key, "[REDACTED]")
					}
				}
				return a
			},
		}

		var handler slog.Handler
		if format == "json" || os.Getenv("CONTAINER") != "" || os.Getenv("DOCKER") != "" {
			handler = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			handler = slog.NewTextHandler(os.Stdout, opts)
		}

		rootLogger = slog.New(handler)
		slog.SetDefault(rootLogger)
	})
	return rootLogger
}

// WithRequestID returns a derived context with the request ID attached.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey, requestID)
}

// RequestIDFromContext extracts the request ID from the context.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(requestIDContextKey).(string); ok {
		return v
	}
	return ""
}

// Log returns an slog.Logger tagged with request context attributes if present.
func Log(ctx context.Context) *slog.Logger {
	logger := InitLogger()
	if reqID := RequestIDFromContext(ctx); reqID != "" {
		return logger.With("request_id", reqID)
	}
	return logger
}
