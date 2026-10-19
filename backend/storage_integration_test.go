package main

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
)

func TestStorageIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated Compose storage test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{ctx: ctx, db: db, state: seed(false)}
	bucket := "surfacer-test-" + id()
	t.Setenv("S3_BUCKET", bucket)
	if err = s.initEvidence(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for item := range s.evidence.client.ListObjects(context.Background(), bucket, minio.ListObjectsOptions{Recursive: true}) {
			_ = s.evidence.client.RemoveObject(context.Background(), bucket, item.Key, minio.RemoveObjectOptions{})
		}
		_ = s.evidence.client.RemoveBucket(context.Background(), bucket)
	}()
	s.state.Targets = []Target{{ID: "storage-target", Domain: "storage-fixture.example", Status: "verified"}}
	sc := Scan{ID: "storage-scan", TargetID: "storage-target", Domain: "storage-fixture.example", Status: "completed", Checkpoint: Checkpoint{Assets: []Asset{{Host: "storage-fixture.example", Type: "Web service", Technologies: []string{}, Ports: []int{443}, Endpoints: []Endpoint{{ID: "fixture-endpoint", URL: "https://storage-fixture.example/api", Method: "GET", Kind: "API endpoint", Parameters: []string{}}}}}, Findings: []Finding{{Host: "storage-fixture.example", Template: "git-config", MatchedAt: "https://storage-fixture.example/.git/config", Title: "Fixture finding", Severity: "medium", Evidence: "DATABASE_PASSWORD=fixture-storage-secret\n"}}}}
	sc.ParentScanID = "prior-storage-attempt"
	sc.Stages = []Stage{{Name: "HTTP probing", Status: "completed", StartedAt: now(), FinishedAt: now()}}
	sc.Checkpoint.ProbeResults = map[string]string{"https://storage-fixture.example": "responded"}
	sc.Checkpoint.DetectionRequired = map[string][]string{"https://storage-fixture.example": {"git-config"}}
	sc.Checkpoint.History = []Endpoint{{ID: "historic-fixture", TargetID: "storage-target", URL: "https://storage-fixture.example/old", Method: "Historical", Historical: true}}
	s.state.Members = []Member{{ID: "fixture-member", Name: "Integration viewer", Role: "viewer", Enabled: true}}
	s.state.AccessKeys = []AccessKey{{ID: "fixture-key", UserID: "fixture-member", Name: "Integration", Hash: tokenDigest("fixture-only"), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}
	sc.Checkpoint.Assets[0].Services = []Service{{URL: "https://storage-fixture.example", Port: 443, Status: 200, TLSVersion: "tls13"}}
	s.normalize(&sc, true)
	s.state.Scans = []Scan{sc}
	s.audit("Storage fixture verified", "Owned integration-test database")
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	beforeHash := s.persisted["workspace_settings:default"]
	originalName := s.state.Settings.Name
	s.state.Settings.Name = "Uncommitted mutation"
	s.state.Findings = append(s.state.Findings, Finding{ID: "invalid-finding", TargetID: "missing-target"})
	if s.save() == nil {
		t.Fatal("invalid target relation accepted")
	}
	if s.persisted["workspace_settings:default"] != beforeHash {
		t.Fatal("failed transaction advanced persistence cache")
	}
	s.state.Findings = s.state.Findings[:len(s.state.Findings)-1]
	s.state.Settings.Name = originalName
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	reloaded := &Server{ctx: ctx, db: db, state: seed(false)}
	if err = reloaded.migrateAndLoad(); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.state.Assets) != 1 || len(reloaded.state.Findings) != 1 || len(reloaded.state.Scans) != 1 || len(reloaded.state.Audit) != 1 {
		t.Fatal("relational round-trip did not retain records")
	}
	if len(reloaded.state.Assets[0].Endpoints) != 1 {
		t.Fatal("endpoint inventory did not persist")
	}
	if len(reloaded.state.History) != 1 || !reloaded.state.History[0].Historical || len(reloaded.state.Members) != 1 || len(reloaded.state.AccessKeys) != 1 || reloaded.state.AccessKeys[0].Hash != tokenDigest("fixture-only") || len(reloaded.state.Assets[0].Services) != 1 {
		t.Fatal("history, services or hashed access did not persist")
	}
	storedScan := reloaded.state.Scans[0]
	if storedScan.ParentScanID != sc.ParentScanID || storedScan.Stages[0].StartedAt == "" || storedScan.Checkpoint.ProbeResults["https://storage-fixture.example"] != "responded" || len(storedScan.Checkpoint.DetectionRequired["https://storage-fixture.example"]) != 1 {
		t.Fatal("scan lineage, timings or service outcomes did not persist")
	}
	finding := reloaded.state.Findings[0]
	if finding.EvidenceKey == "" {
		t.Fatal("S3 evidence reference missing")
	}
	object, err := s.evidence.client.GetObject(ctx, bucket, finding.EvidenceKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(object)
	object.Close()
	if err != nil || strings.Contains(string(b), "fixture-storage-secret") || !strings.Contains(string(b), "[REDACTED]") {
		t.Fatal("evidence round-trip/redaction failed")
	}
	if _, err = db.Exec(ctx, "UPDATE audit_log SET data=data"); err == nil {
		t.Fatal("runtime role can update audit entries")
	}
	if _, err = db.Exec(ctx, "CREATE TABLE forbidden_runtime_ddl (id integer)"); err == nil {
		t.Fatal("runtime role can mutate schema")
	}
	t.Log("Postgres records, MinIO evidence, redaction, and database role restrictions verified")
}
