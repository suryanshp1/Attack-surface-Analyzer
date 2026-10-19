package main

import (
	"fmt"
	"strings"
)

// deleteFindings runs under the workspace lock. Tombstones use the existing
// JSON/JSONB persistence path, retaining fingerprints, triage and first-seen
// history without granting the application role SQL DELETE permissions.
func (s *Server) deleteFindings(ids []string) (int, error) {
	if len(ids) == 0 || len(ids) > 100 {
		return 0, fmt.Errorf("select between 1 and 100 finding IDs per request")
	}
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !mcpEntityID.MatchString(id) || selected[id] {
			return 0, fmt.Errorf("finding IDs must be valid and unique")
		}
		selected[id] = true
	}
	// Validate the complete batch before mutating any record. Already-deleted
	// IDs are accepted so a client can safely retry after a lost response.
	found := 0
	for _, f := range s.state.Findings {
		if selected[f.ID] {
			found++
		}
	}
	if found != len(selected) {
		return 0, fmt.Errorf("one or more findings no longer exist; refresh and retry")
	}
	stamp := now()
	deleted := []string{}
	targets := map[string]bool{}
	for i := range s.state.Findings {
		f := &s.state.Findings[i]
		if selected[f.ID] && f.DeletedAt == "" {
			f.DeletedAt = stamp
			deleted = append(deleted, f.ID)
			targets[f.TargetID] = true
		}
	}
	for target := range targets {
		s.recountAssetFindings(target)
	}
	if len(deleted) > 0 {
		s.audit("Findings deleted", fmt.Sprintf("%d record(s): %s", len(deleted), strings.Join(deleted, ", ")))
	}
	return len(deleted), nil
}
