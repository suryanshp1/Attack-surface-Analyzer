package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func mcpReadAnnotations() *mcp.ToolAnnotations {
	closed := false
	return &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closed}
}

func mcpWriteAnnotations(destructive, external bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{DestructiveHint: &destructive, OpenWorldHint: &external}
}

func mcpObjectSchema(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func mcpIDProperty() map[string]any {
	return map[string]any{"type": "string", "pattern": mcpEntityID.String(), "minLength": 1, "maxLength": 128}
}

func mcpIDSchema(name string) map[string]any {
	return mcpObjectSchema(map[string]any{name: mcpIDProperty()}, name)
}

func mcpListSchema(kind string) map[string]any {
	target := mcpIDProperty()
	target["pattern"], target["minLength"] = "^([a-zA-Z0-9_-]{1,128})?$", 0
	properties := map[string]any{
		"targetId": target,
		"offset":   map[string]any{"type": "integer", "minimum": 0, "description": "Zero-based offset, default 0"},
		"limit":    map[string]any{"type": "integer", "minimum": 0, "maximum": 100, "description": "Page size, default 25; 0 also uses the default. Byte bounds can produce shorter pages; follow nextOffset."},
		"status":   map[string]any{"type": "string", "description": "Exact status for targets, findings or scans; not supported for assets or endpoints"},
		"severity": map[string]any{"type": "string", "enum": []string{"none", "info", "low", "medium", "high", "critical"}, "description": "Exact severity for assets or findings only"},
	}
	if kind != "targets" && kind != "findings" && kind != "scans" {
		delete(properties, "status")
	}
	if kind != "assets" && kind != "findings" {
		delete(properties, "severity")
	}
	return mcpObjectSchema(properties)
}

func mcpTriageSchema() map[string]any {
	return mcpObjectSchema(map[string]any{
		"findingId": mcpIDProperty(),
		"status":    map[string]any{"type": "string", "enum": []string{"open", "accepted risk", "false positive"}},
		"note":      map[string]any{"type": "string", "minLength": 3, "maxLength": 2000},
	}, "findingId", "status", "note")
}

func validateMCPListFilters(kind string, args mcpListArgs) error {
	if args.TargetID != "" && !mcpEntityID.MatchString(args.TargetID) {
		return fmt.Errorf("invalid target ID")
	}
	if args.Status != "" {
		statuses := map[string][]string{
			"targets":  {"pending", "verified", "paused"},
			"findings": {"open", "resolved", "accepted risk", "false positive"},
			"scans":    {"queued", "retrying", "running", "completed", "partial", "failed", "canceled"},
		}
		if !contains(statuses[kind], args.Status) {
			return fmt.Errorf("unsupported status filter for %s", kind)
		}
	}
	if args.Severity != "" && ((kind != "findings" && kind != "assets") || !contains([]string{"none", "info", "low", "medium", "high", "critical"}, args.Severity)) {
		return fmt.Errorf("severity filter requires assets or findings and a valid severity")
	}
	return nil
}

func (s *Server) mcpGetScan(ctx context.Context, req *mcp.CallToolRequest, scanID string) (any, error) {
	if !mcpEntityID.MatchString(scanID) {
		return nil, fmt.Errorf("invalid scan ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.memberActorLocked(mcpRequest(ctx, req, "GET", "/api/state", nil)); !ok {
		return nil, fmt.Errorf("access key expired, revoked, or disabled")
	}
	for _, scan := range s.state.Scans {
		if scan.ID != scanID {
			continue
		}
		raw, err := json.Marshal(publicScan(scan))
		if err != nil {
			return nil, err
		}
		if len(raw) > (1<<20)-4096 {
			return nil, fmt.Errorf("scan exceeds bounded MCP response size")
		}
		return map[string]any{"scan": json.RawMessage(raw), "runtime": s.publicRuntime(), "scanningPaused": s.state.Settings.Paused}, nil
	}
	return nil, fmt.Errorf("scan not found")
}
