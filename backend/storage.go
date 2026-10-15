package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

//go:embed schema.sql
var schemaSQL string

func (s *Server) migrateAndLoad() error {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	if os.Getenv("RUN_MIGRATIONS") == "true" {
		if _, err := s.db.Exec(ctx, schemaSQL); err != nil {
			return err
		}
	}
	var settings []byte
	err := s.db.QueryRow(ctx, "SELECT data FROM workspace_settings WHERE id='default'").Scan(&settings)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if e := s.db.QueryRow(ctx, "SELECT to_regclass('public.workspace_state') IS NOT NULL").Scan(&exists); e == nil && exists {
			var old []byte
			if e = s.db.QueryRow(ctx, "SELECT data FROM workspace_state WHERE id=1").Scan(&old); e == nil {
				return json.Unmarshal(old, &s.state)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(settings, &s.state.Settings); err != nil {
		return err
	}
	s.state.History = []Endpoint{}
	var runtimeJSON []byte
	if e := s.db.QueryRow(ctx, "SELECT data FROM workspace_runtime WHERE id='default'").Scan(&runtimeJSON); e == nil {
		var stored State
		if json.Unmarshal(runtimeJSON, &stored) == nil {
			s.state.Members = stored.Members
			s.state.AccessKeys = stored.AccessKeys
		}
	}
	s.state.Targets = []Target{}
	s.state.Scans = []Scan{}
	s.state.Assets = []Asset{}
	s.state.Findings = []Finding{}
	s.state.Events = []Event{}
	s.state.Audit = []Event{}
	for _, table := range []string{"targets", "scans", "assets", "findings", "historical_endpoints", "change_events", "audit_log"} {
		rows, err := s.db.Query(ctx, "SELECT data FROM "+table+" WHERE workspace_id='default' ORDER BY COALESCE(data->>'at',data->>'startedAt',data->>'firstSeen','') DESC")
		if err != nil {
			return err
		}
		for rows.Next() {
			var b []byte
			if err = rows.Scan(&b); err != nil {
				rows.Close()
				return err
			}
			switch table {
			case "historical_endpoints":
				var v Endpoint
				err = json.Unmarshal(b, &v)
				s.state.History = append(s.state.History, v)
			case "targets":
				var v Target
				err = json.Unmarshal(b, &v)
				s.state.Targets = append(s.state.Targets, v)
			case "scans":
				var v Scan
				err = json.Unmarshal(b, &v)
				s.state.Scans = append(s.state.Scans, v)
			case "assets":
				var v Asset
				err = json.Unmarshal(b, &v)
				s.state.Assets = append(s.state.Assets, v)
			case "findings":
				var v Finding
				err = json.Unmarshal(b, &v)
				s.state.Findings = append(s.state.Findings, v)
			case "change_events":
				var v Event
				err = json.Unmarshal(b, &v)
				s.state.Events = append(s.state.Events, v)
			case "audit_log":
				var v Event
				err = json.Unmarshal(b, &v)
				s.state.Audit = append(s.state.Audit, v)
			}
			if err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	s.state.Demo = false
	for _, t := range s.state.Targets {
		if t.Demo {
			s.state.Demo = true
		}
	}
	return nil
}
func (s *Server) saveRelational() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	pending := map[string]string{}
	for key, value := range s.persisted {
		pending[key] = value
	}
	put := func(table, id, target string, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		cacheKey := table + ":" + id
		digest := tokenDigest(string(b))
		if s.persisted[cacheKey] == digest {
			return nil
		}
		pending[cacheKey] = digest
		query := "INSERT INTO " + table + "(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data WHERE " + table + ".data IS DISTINCT FROM EXCLUDED.data"
		args := []any{id, b}
		if target != "" {
			query = "INSERT INTO " + table + "(id,target_id,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data WHERE " + table + ".data IS DISTINCT FROM EXCLUDED.data"
			args = []any{id, target, b}
		}
		if table == "audit_log" || table == "change_events" {
			query = "INSERT INTO " + table + "(id,data) VALUES($1,$2) ON CONFLICT(id) DO NOTHING"
		}
		_, e = tx.Exec(ctx, query, args...)
		return e
	}
	if err = put("workspace_settings", "default", "", s.state.Settings); err != nil {
		return err
	}
	if err = put("workspace_runtime", "default", "", State{Members: s.state.Members, AccessKeys: s.state.AccessKeys}); err != nil {
		return err
	}
	for _, t := range s.state.Targets {
		if err = put("targets", t.ID, "", t); err != nil {
			return err
		}
	}
	for _, e := range s.state.History {
		if err = put("historical_endpoints", e.ID, e.TargetID, e); err != nil {
			return err
		}
	}
	for _, sc := range s.state.Scans {
		if err = put("scans", sc.ID, sc.TargetID, sc); err != nil {
			return err
		}
	}
	for _, a := range s.state.Assets {
		if err = put("assets", a.ID, a.TargetID, a); err != nil {
			return err
		}
	}
	for _, f := range s.state.Findings {
		target := f.TargetID
		if target == "" {
			for _, t := range s.state.Targets {
				if inScope(f.Host, t.Domain) {
					target = t.ID
					break
				}
			}
		}
		if target == "" {
			return fmt.Errorf("finding %s has no target", f.ID)
		}
		if err = put("findings", f.ID, target, f); err != nil {
			return err
		}
	}
	for _, e := range s.state.Events {
		if err = put("change_events", e.ID, "", e); err != nil {
			return err
		}
	}
	for _, e := range s.state.Audit {
		if err = put("audit_log", e.ID, "", e); err != nil {
			return err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	s.persisted = pending
	return nil
}

type EvidenceStore struct {
	client *minio.Client
	bucket string
}

func (s *Server) initEvidence() error {
	endpoint := os.Getenv("S3_ENDPOINT")
	if endpoint == "" {
		if s.liveEnabled {
			return errors.New("S3_ENDPOINT required for live scanning")
		}
		return nil
	}
	client, err := minio.New(endpoint, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("S3_ACCESS_KEY"), os.Getenv("S3_SECRET_KEY"), ""), Secure: os.Getenv("S3_TLS") == "true"})
	if err != nil {
		return err
	}
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		bucket = "surfacer-evidence"
	}
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !exists {
		if err = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return err
		}
	}
	s.evidence = &EvidenceStore{client, bucket}
	return nil
}
func (s *EvidenceStore) put(ctx context.Context, key string, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(b), int64(len(b)), minio.PutObjectOptions{ContentType: "text/plain; charset=utf-8"})
	return err
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)((?:password|passwd|pass|secret|token|app[_-]?key|api[_-]?key|access[_-]?key|authorization|cookie|set-cookie)[\w-]*\s*[:=]\s*)[^\r\n]+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`), regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`), regexp.MustCompile(`(?s)-----BEGIN[^\n]*PRIVATE KEY-----.*?-----END[^\n]*PRIVATE KEY-----`), regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
}

func redact(value string) string {
	value = regexp.MustCompile(`(https?://)[^/\s:@]+:[^@\s]+@`).ReplaceAllString(value, `${1}[REDACTED]@`)
	for i, p := range secretPatterns {
		replacement := "[REDACTED]"
		if i == 0 {
			replacement = "${1}[REDACTED]"
		}
		value = p.ReplaceAllString(value, replacement)
	}
	return strings.ReplaceAll(value, "\x00", "")
}

func (s *Server) cleanupEvidence() {
	s.mu.Lock()
	store := s.evidence
	days := s.state.Settings.Retention
	s.mu.Unlock()
	if store == nil {
		return
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	for item := range store.client.ListObjects(ctx, store.bucket, minio.ListObjectsOptions{Recursive: true}) {
		if item.Err != nil {
			return
		}
		if item.LastModified.Before(cutoff) {
			if err := store.client.RemoveObject(ctx, store.bucket, item.Key, minio.RemoveObjectOptions{}); err != nil {
				return
			}
		}
	}
}

func runMigrations() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	defer db.Close(ctx)
	pass := os.Getenv("POSTGRES_APP_PASSWORD")
	if len(pass) < 32 {
		panic("POSTGRES_APP_PASSWORD must contain at least 32 characters")
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='surfacer_app')").Scan(&exists); err != nil {
		panic(err)
	}
	if !exists {
		if _, err = tx.Exec(ctx, "CREATE ROLE surfacer_app LOGIN"); err != nil {
			panic(err)
		}
	}
	if _, err = tx.Exec(ctx, "ALTER ROLE surfacer_app PASSWORD '"+strings.ReplaceAll(pass, "'", "''")+"'"); err != nil {
		panic("Could not configure the application database role")
	}
	if _, err = tx.Exec(ctx, schemaSQL); err != nil {
		panic(err)
	}
	if _, err = tx.Exec(ctx, `GRANT USAGE ON SCHEMA public TO surfacer_app; REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT SELECT,INSERT,UPDATE ON workspace_settings,workspace_runtime,targets,scans,assets,findings,historical_endpoints TO surfacer_app; GRANT SELECT,INSERT ON audit_log,change_events TO surfacer_app; GRANT SELECT ON schema_migrations,v_scans,v_audit_log,v_scan_stages TO surfacer_app;`); err != nil {
		panic(err)
	}
	if err = tx.Commit(ctx); err != nil {
		panic(err)
	}
	fmt.Println("Database migrations applied; runtime role cannot mutate audit entries or schema.")
}
