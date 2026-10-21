package main

import (
	"fmt"
	"sort"
	"strings"
)

type SurfaceChange struct {
	TargetID       string   `json:"targetId"`
	ScanID         string   `json:"scanId"`
	PreviousScanID string   `json:"previousScanId"`
	Host           string   `json:"host"`
	Origin         string   `json:"origin,omitempty"`
	Field          string   `json:"field"`
	Before         []string `json:"before"`
	After          []string `json:"after"`
}

func changeValues(values []string) []string {
	out := dedupeStrings(append([]string{}, values...))
	sort.Strings(out)
	return out
}

// Compare immutable successful scan observations, not the live inventory that
// progressive publication may already have overwritten. Missing data is unknown.
func (s *Server) recordSurfaceChanges(sc *Scan, stamp string) {
	if sc.ID == "" {
		return
	}
	var previous *Scan
	for i := range s.state.Scans {
		candidate := &s.state.Scans[i]
		if candidate.StartedAt == "" || candidate.ID == sc.ID || candidate.TargetID != sc.TargetID || candidate.Status != "completed" || candidate.StartedAt >= sc.StartedAt {
			continue
		}
		if previous == nil || candidate.StartedAt > previous.StartedAt {
			previous = candidate
		}
	}
	if previous == nil {
		return
	}
	seen := map[string]bool{}
	for _, event := range s.state.Events {
		seen[event.ID] = true
	}
	emit := func(host, origin, field string, before, after []string) {
		before, after = changeValues(before), changeValues(after)
		if len(before) == 0 || len(after) == 0 || strings.Join(before, "\x00") == strings.Join(after, "\x00") {
			return
		}
		key := fingerprint(sc.ID, host, origin, field)
		if seen[key] {
			return
		}
		kind := "asset"
		if field == "certificateExpiry" || field == "certificateIssuer" || field == "certificateNames" {
			kind = "certificate"
		}
		if field == "ports" {
			kind = "port"
		}
		title := map[string]string{"dnsAddresses": "DNS addresses changed", "ports": "Observed ports changed", "technologies": "Technology observations changed", "certificateExpiry": "Certificate expiry changed", "certificateIssuer": "Certificate issuer changed", "certificateNames": "Certificate names changed"}[field]
		detail := fmt.Sprintf("%s · %s → %s", host, strings.Join(before, ", "), strings.Join(after, ", "))
		event := Event{ID: key, Kind: kind, Title: title, Detail: detail, At: stamp, Actor: "Surfacer", Change: &SurfaceChange{TargetID: sc.TargetID, ScanID: sc.ID, PreviousScanID: previous.ID, Host: host, Origin: origin, Field: field, Before: before, After: after}}
		s.state.Events = append([]Event{event}, s.state.Events...)
		seen[key] = true
	}
	oldAssets := map[string]Asset{}
	for _, a := range previous.Checkpoint.Assets {
		oldAssets[a.Host] = a
	}
	for _, a := range sc.Checkpoint.Assets {
		old, ok := oldAssets[a.Host]
		if !ok || a.Blocked || old.Blocked {
			continue
		}
		emit(a.Host, "", "dnsAddresses", previous.Checkpoint.DNS[a.Host], sc.Checkpoint.DNS[a.Host])
		portsComplete := func(cp Checkpoint, host string) bool {
			if len(cp.DNS[host]) == 0 || contains(cp.PortIncomplete, host) {
				return false
			}
			for _, ip := range cp.DNS[host] {
				if _, ok := cp.PortResults[ip]; !ok {
					return false
				}
			}
			return true
		}
		if portsComplete(previous.Checkpoint, a.Host) && portsComplete(sc.Checkpoint, a.Host) {
			emit(a.Host, "", "ports", intStrings(old.Ports), intStrings(a.Ports))
		}
		oldServices := map[string]Service{}
		for _, svc := range old.Services {
			oldServices[serviceOrigin(svc.URL)] = svc
		}
		for _, svc := range a.Services {
			origin := serviceOrigin(svc.URL)
			prior, ok := oldServices[origin]
			if !ok || previous.Checkpoint.ProbeResults[origin] != "responded" || sc.Checkpoint.ProbeResults[origin] != "responded" {
				continue
			}
			emit(a.Host, origin, "technologies", prior.Technologies, svc.Technologies)
			emit(a.Host, origin, "certificateExpiry", nonempty(prior.CertificateExpiry), nonempty(svc.CertificateExpiry))
			emit(a.Host, origin, "certificateIssuer", nonempty(prior.Issuer), nonempty(svc.Issuer))
			emit(a.Host, origin, "certificateNames", prior.CertificateNames, svc.CertificateNames)
		}
	}
}

func nonempty(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}
