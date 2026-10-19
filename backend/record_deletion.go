package main

import (
	"errors"
	"fmt"
	"strings"
)

var errActiveScanDeletion = errors.New("only completed, partial, failed, or canceled scans can be deleted; cancel active scans first")

func deletableResource(resource string) bool {
	return contains([]string{"findings", "assets", "endpoints", "scans", "hazards", "takeovers"}, resource)
}

func (s *Server) recordDeleted(resource, id string) bool {
	return s.state.RecordDeletions[resource+":"+id] != ""
}

func (s *Server) deleteRecords(resource string, ids []string) (int, error) {
	if resource == "findings" {
		return s.deleteFindings(ids)
	}
	if !deletableResource(resource) || len(ids) == 0 || len(ids) > 100 {
		return 0, fmt.Errorf("select between 1 and 100 record IDs per request")
	}
	selected := map[string]bool{}
	for _, id := range ids {
		if !mcpEntityID.MatchString(id) || selected[id] {
			return 0, fmt.Errorf("record IDs must be valid and unique")
		}
		selected[id] = true
	}
	found := map[string]bool{}
	check := func(id string) {
		if selected[id] {
			found[id] = true
		}
	}
	switch resource {
	case "assets":
		for _, a := range s.state.Assets {
			check(a.ID)
		}
	case "endpoints":
		for _, a := range s.state.Assets {
			for _, e := range a.Endpoints {
				check(e.ID)
			}
		}
		for _, e := range s.state.History {
			check(e.ID)
		}
	case "scans":
		for _, sc := range s.state.Scans {
			if selected[sc.ID] && !contains([]string{"completed", "partial", "failed", "canceled"}, sc.Status) {
				return 0, errActiveScanDeletion
			}
			check(sc.ID)
		}
	case "hazards":
		for _, h := range s.state.Hazards {
			check(h.ID)
		}
	case "takeovers":
		for _, to := range s.state.Takeovers {
			check(to.ID)
		}
	}
	if len(found) != len(selected) {
		return 0, fmt.Errorf("one or more records no longer exist; refresh and retry")
	}
	if s.state.RecordDeletions == nil {
		s.state.RecordDeletions = map[string]string{}
	}
	deleted := []string{}
	for _, id := range ids {
		if !s.recordDeleted(resource, id) {
			s.state.RecordDeletions[resource+":"+id] = now()
			deleted = append(deleted, id)
		}
	}
	if len(deleted) > 0 {
		s.audit("Records deleted", fmt.Sprintf("%s: %d record(s): %s", resource, len(deleted), strings.Join(deleted, ", ")))
	}
	return len(deleted), nil
}

func (s *Server) visibleEndpoints(endpoints []Endpoint) []Endpoint {
	out := []Endpoint{}
	for _, e := range endpoints {
		if !s.recordDeleted("endpoints", e.ID) {
			out = append(out, e)
		}
	}
	return out
}

func (s *Server) visibleAsset(a Asset) Asset {
	a = publicAsset(a)
	a.Endpoints = s.visibleEndpoints(a.Endpoints)
	return a
}

// A new, non-resumed scan can restore genuinely observed records. Existing
// runs and retained recovery checkpoints cannot silently undo manual deletion.
// Finished scan history is never automatically restored or discarded internally.
func (s *Server) restoreObservedRecords(sc *Scan) {
	if sc.ParentScanID != "" || sc.StartedAt == "" {
		return
	}
	restore := func(resource, id string) {
		key := resource + ":" + id
		if stamp := s.state.RecordDeletions[key]; stamp != "" && sc.StartedAt > stamp {
			delete(s.state.RecordDeletions, key)
		}
	}
	for _, a := range sc.Checkpoint.Assets {
		restore("assets", fingerprint(sc.TargetID, a.Host))
		for _, e := range a.Endpoints {
			restore("endpoints", e.ID)
		}
	}
	for _, e := range sc.Checkpoint.History {
		restore("endpoints", e.ID)
	}
	for _, h := range sc.Checkpoint.Hazards {
		for _, old := range s.state.Hazards {
			if h.URL == old.URL && h.Parameter == old.Parameter && h.HazardClass == old.HazardClass {
				restore("hazards", old.ID)
			}
		}
	}
	for _, to := range sc.Checkpoint.Takeovers {
		for _, old := range s.state.Takeovers {
			if to.Subdomain == old.Subdomain && to.ServiceProvider == old.ServiceProvider {
				restore("takeovers", old.ID)
			}
		}
	}
}
