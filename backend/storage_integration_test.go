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
	score := 0.0
	sc.Checkpoint.Findings[0].CVEs = []string{"CVE-2020-11022"}
	sc.Checkpoint.Findings[0].CVSSScore = &score
	sc.Checkpoint.Findings[0].Dependency = &DependencyObservation{Name: "jquery", Version: "1.12.4", Detection: "filecontent", Database: retireDatabase}
	sc.Checkpoint.KnownLibraries = []Finding{libraryFinding("https://storage-fixture.example/app.js")}
	sc.Checkpoint.LibraryCoverage = map[string][]string{"https://storage-fixture.example/app.js": {"retire:jquery:fixture"}}
	s.state.Events = []Event{{ID: "storage-change", Kind: "certificate", Title: "Certificate expiry changed", Change: &SurfaceChange{TargetID: "storage-target", ScanID: sc.ID, PreviousScanID: "prior-storage-attempt", Host: "storage-fixture.example", Field: "certificateExpiry", Before: []string{"2026-01-01"}, After: []string{"2026-06-01"}}}}
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
	if finding.Dependency == nil || finding.Dependency.Database != retireDatabase || finding.CVSSScore == nil || *finding.CVSSScore != 0 || !contains(finding.CVEs, "CVE-2020-11022") {
		t.Fatal("vulnerability metadata did not persist")
	}
	if len(storedScan.Checkpoint.KnownLibraries) != 1 || len(storedScan.Checkpoint.LibraryCoverage) != 1 {
		t.Fatal("library coverage did not persist")
	}
	changeFound := false
	for _, e := range reloaded.state.Events {
		if e.ID == "storage-change" && e.Change != nil && e.Change.PreviousScanID == "prior-storage-attempt" {
			changeFound = true
		}
	}
	if !changeFound {
		t.Fatal("structured changes did not persist")
	}
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
	if count, err := s.deleteFindings([]string{finding.ID}); err != nil || count != 1 {
		t.Fatal("could not delete finding with restricted application role", count, err)
	}
	if err = s.save(); err != nil {
		t.Fatal("could not persist finding tombstone", err)
	}
	deletedReload := &Server{ctx: ctx, db: db, state: seed(false)}
	if err = deletedReload.migrateAndLoad(); err != nil {
		t.Fatal(err)
	}
	if len(deletedReload.publicState().Findings) != 0 || len(deletedReload.state.Findings) != 1 || deletedReload.state.Findings[0].DeletedAt == "" || deletedReload.state.Findings[0].FirstSeen != finding.FirstSeen || deletedReload.state.Findings[0].EvidenceKey != finding.EvidenceKey {
		t.Fatal("PostgreSQL reload lost deletion or retained history")
	}
	for resource, ids := range map[string][]string{"assets": {s.state.Assets[0].ID}, "endpoints": {"fixture-endpoint", "historic-fixture"}, "scans": {"storage-scan"}} {
		if _, err := s.deleteRecords(resource, ids); err != nil {
			t.Fatal(resource, err)
		}
	}
	if err = s.save(); err != nil {
		t.Fatal(err)
	}
	recordReload := &Server{ctx: ctx, db: db, state: seed(false)}
	if err = recordReload.migrateAndLoad(); err != nil {
		t.Fatal(err)
	}
	visible := recordReload.publicState()
	if len(visible.Assets) != 0 || len(visible.Scans) != 0 || len(visible.History) != 0 || len(recordReload.state.Assets) != 1 || len(recordReload.state.Scans) != 1 || len(recordReload.state.RecordDeletions) != 4 {
		t.Fatal("PostgreSQL runtime metadata did not retain record deletions and history")
	}
	t.Log("Postgres records, MinIO evidence, redaction, and database role restrictions verified")
}
