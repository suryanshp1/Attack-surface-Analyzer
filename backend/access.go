package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

type Member struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt"`
}
type AccessKey struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UserID    string `json:"userId"`
	Hash      string `json:"hash,omitempty"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
	Revoked   bool   `json:"revoked"`
}
type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

func tokenDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func validRole(role string) bool { return role == "owner" || role == "analyst" || role == "viewer" }
func (s *Server) actorLocked(r *http.Request) (Actor, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	configured := os.Getenv("API_TOKEN")
	if configured == "" || subtle.ConstantTimeCompare([]byte(token), []byte(configured)) == 1 {
		return Actor{"owner", "Workspace owner", "owner"}, true
	}
	hash := tokenDigest(token)
	for _, key := range s.state.AccessKeys {
		expiry, err := time.Parse(time.RFC3339, key.ExpiresAt)
		if key.Revoked || err != nil || time.Now().After(expiry) || subtle.ConstantTimeCompare([]byte(hash), []byte(key.Hash)) != 1 {
			continue
		}
		for _, member := range s.state.Members {
			if member.ID == key.UserID && member.Enabled && validRole(member.Role) {
				return Actor{member.ID, member.Name, member.Role}, true
			}
		}
	}
	return Actor{}, false
}
func (s *Server) actor(r *http.Request) (Actor, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actorLocked(r)
}
func canWrite(actor Actor, path string) bool {
	if actor.Role == "owner" {
		return true
	}
	if actor.Role == "viewer" {
		return false
	}
	return strings.HasPrefix(path, "findings/") || path == "scans" || strings.HasPrefix(path, "scans/") || (path == "api-keys" || strings.HasPrefix(path, "api-keys/"))
}
func (s *Server) publicStateFor(actor Actor) State {
	out := s.publicState()
	out.Me = actor
	out.AccessKeys = append([]AccessKey{}, s.state.AccessKeys...)
	for i := range out.AccessKeys {
		out.AccessKeys[i].Hash = ""
	}
	if actor.Role != "owner" {
		out.Members = []Member{}
		keys := []AccessKey{}
		for _, k := range out.AccessKeys {
			if k.UserID == actor.ID {
				keys = append(keys, k)
			}
		}
		out.AccessKeys = keys
		out.Audit = []Event{}
	}
	return out
}
func (s *Server) accessAPI(w http.ResponseWriter, r *http.Request, path string, actor Actor) bool {
	before, _ := json.Marshal(s.state)
	tracked := &accessResponse{ResponseWriter: w}
	w = tracked
	defer func() {
		if tracked.status >= 500 {
			_ = json.Unmarshal(before, &s.state)
		}
	}()

	if path == "me" && r.Method == "GET" {
		respond(w, 200, actor)
		return true
	}
	if path == "members" && r.Method == "POST" {
		var p struct{ Name, Role string }
		if !decode(w, r, &p) {
			return true
		}
		if actor.Role != "owner" || len(strings.TrimSpace(p.Name)) < 2 || len(p.Name) > 100 || !validRole(p.Role) {
			fail(w, 400, "Owner access, member name and valid role required")
			return true
		}
		if len(s.state.Members) >= 100 {
			fail(w, 409, "Member limit reached")
			return true
		}
		member := Member{id(), strings.TrimSpace(p.Name), p.Role, true, now()}
		raw := "surf_key_" + id() + id()
		key := AccessKey{ID: id(), Name: "Initial access", UserID: member.ID, Hash: tokenDigest(raw), CreatedAt: now(), ExpiresAt: time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)}
		s.state.Members = append(s.state.Members, member)
		s.state.AccessKeys = append(s.state.AccessKeys, key)
		s.audit("Member access created", member.Name+" · "+member.Role)
		if err := s.save(); err != nil {
			s.state.Members = s.state.Members[:len(s.state.Members)-1]
			s.state.AccessKeys = s.state.AccessKeys[:len(s.state.AccessKeys)-1]
			fail(w, 500, "Could not persist access")
			return true
		}
		respond(w, 201, map[string]any{"member": member, "token": raw, "expiresAt": key.ExpiresAt})
		return true
	}
	if strings.HasPrefix(path, "members/") && r.Method == "PATCH" {
		var p struct {
			Role    string `json:"role"`
			Enabled bool   `json:"enabled"`
		}
		if !decode(w, r, &p) {
			return true
		}
		if actor.Role != "owner" || !validRole(p.Role) {
			fail(w, 403, "Owner access required")
			return true
		}
		for i, m := range s.state.Members {
			if m.ID == strings.TrimPrefix(path, "members/") {
				old := m
				s.state.Members[i].Role = p.Role
				s.state.Members[i].Enabled = p.Enabled
				s.audit("Member access updated", m.Name+" · "+p.Role)
				if err := s.save(); err != nil {
					s.state.Members[i] = old
					fail(w, 500, "Could not persist member")
					return true
				}
				respond(w, 200, s.state.Members[i])
				return true
			}
		}
		fail(w, 404, "Member not found")
		return true
	}
	if path == "api-keys" && r.Method == "POST" {
		var p struct {
			Name   string `json:"name"`
			UserID string `json:"userId"`
			Days   int    `json:"days"`
		}
		if !decode(w, r, &p) {
			return true
		}
		if p.UserID == "" {
			p.UserID = actor.ID
		}
		if actor.Role != "owner" && p.UserID != actor.ID {
			fail(w, 403, "Cannot issue keys for another member")
			return true
		}
		if p.Days < 1 || p.Days > 90 || len(p.Name) < 2 || len(p.Name) > 80 {
			fail(w, 400, "Key name and expiry of 1–90 days required")
			return true
		}
		found := false
		for _, m := range s.state.Members {
			if m.ID == p.UserID && m.Enabled {
				found = true
			}
		}
		if !found {
			fail(w, 400, "Choose an enabled member")
			return true
		}
		raw := "surf_key_" + id() + id()
		key := AccessKey{ID: id(), Name: p.Name, UserID: p.UserID, Hash: tokenDigest(raw), CreatedAt: now(), ExpiresAt: time.Now().Add(time.Duration(p.Days) * 24 * time.Hour).UTC().Format(time.RFC3339)}
		s.state.AccessKeys = append(s.state.AccessKeys, key)
		s.audit("API key issued", p.Name)
		if err := s.save(); err != nil {
			s.state.AccessKeys = s.state.AccessKeys[:len(s.state.AccessKeys)-1]
			fail(w, 500, "Could not persist key")
			return true
		}
		respond(w, 201, map[string]any{"key": AccessKey{ID: key.ID, Name: key.Name, UserID: key.UserID, CreatedAt: key.CreatedAt, ExpiresAt: key.ExpiresAt}, "token": raw})
		return true
	}
	if strings.HasPrefix(path, "api-keys/") && strings.HasSuffix(path, "/revoke") && r.Method == "POST" {
		for i, k := range s.state.AccessKeys {
			if k.ID == strings.TrimSuffix(strings.TrimPrefix(path, "api-keys/"), "/revoke") {
				if actor.Role != "owner" && actor.ID != k.UserID {
					fail(w, 403, "Key owner required")
					return true
				}
				s.state.AccessKeys[i].Revoked = true
				s.audit("API key revoked", k.Name)
				if err := s.save(); err != nil {
					s.state.AccessKeys[i].Revoked = k.Revoked
					fail(w, 500, "Could not persist revocation")
					return true
				}
				respond(w, 200, map[string]bool{"ok": true})
				return true
			}
		}
		fail(w, 404, "Key not found")
		return true
	}
	return false
}

type accessResponse struct {
	http.ResponseWriter
	status int
}

func (w *accessResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
