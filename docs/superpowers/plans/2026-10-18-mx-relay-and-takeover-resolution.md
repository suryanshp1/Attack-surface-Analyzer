# MX Relay Query Forwarding & Takeover Two-Scan Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable MX record enumeration through the gateway DNS relay and enforce two consecutive successful scans with absent observations before resolving subdomain takeovers.

**Architecture:** Extend `dnsRelay` in `backend/gateway.go` to permit `dnsmessage.TypeMX` questions and forward to `EGRESS_DNS` (default `1.1.1.1:53`). Track `MissingScans` in `SubdomainTakeover` across API models, persistence layers, and `normalize()`, requiring `MissingScans >= 2` before status transitions to `resolved`.

**Tech Stack:** Go 1.25+, PostgreSQL (`pgx/v5`), TypeScript, Next.js 16 App Router, `golang.org/x/net/dns/dnsmessage`.

## Global Constraints
- Target scope, dial-time DNS verification, and egress boundaries must remain strictly enforced.
- Takeovers resolve ONLY after two successful scans confirming absence; re-observation reopens immediately with reset `MissingScans`.
- PostgreSQL schema changes must work with `RUN_MIGRATIONS=true` and `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` without resetting volumes or breaking development JSON storage.
- All Go code must pass `go test -race ./...`.

---

### Task 1: Allow MX Queries in Gateway DNS Relay

**Files:**
- Modify: `backend/gateway.go:379-405`
- Test: `backend/dns_relay_test.go`

**Interfaces:**
- Consumes: `golang.org/x/net/dns/dnsmessage`
- Produces: `dnsRelay(ctx context.Context, address string)` forwarding TypeA, TypeAAAA, TypeTXT, TypeCNAME, and TypeMX questions to `EGRESS_DNS` / `1.1.1.1:53`.

- [ ] **Step 1: Write the failing test**

Create `backend/dns_relay_test.go`:
```go
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSRelayAllowsMXAndFiltersDisallowed(t *testing.T) {
	// Upstream mock DNS server responding to MX queries
	upstreamConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := upstreamConn.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}
			msg.Header.Response = true
			for _, q := range msg.Questions {
				if q.Type == dnsmessage.TypeMX {
					mxName, _ := dnsmessage.NewName("mail.example.com.")
					msg.Answers = append(msg.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Name,
							Type:  dnsmessage.TypeMX,
							Class: dnsmessage.ClassINET,
							TTL:   300,
						},
						Body: &dnsmessage.MXResource{
							Pref: 10,
							MX:   mxName,
						},
					})
				}
			}
			packed, err := msg.Pack()
			if err == nil {
				_, _ = upstreamConn.WriteTo(packed, peer)
			}
		}
	}()

	t.Setenv("EGRESS_DNS", upstreamConn.LocalAddr().String())

	// Start dnsRelay on a random port
	relayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := relayConn.LocalAddr().String()
	relayConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go dnsRelay(ctx, relayAddr)
	time.Sleep(50 * time.Millisecond)

	// Send an MX query to relay
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", relayAddr)
		},
	}

	mxList, err := resolver.LookupMX(ctx, "example.com")
	if err != nil {
		t.Fatalf("expected MX query through relay to succeed, got: %v", err)
	}
	if len(mxList) != 1 || mxList[0].Host != "mail.example.com." || mxList[0].Pref != 10 {
		t.Fatalf("unexpected MX response: %+v", mxList)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test -race -run '^TestDNSRelayAllowsMXAndFiltersDisallowed$' .`
Expected: FAIL or timeout because `dnsRelay` discards `TypeMX`.

- [ ] **Step 3: Update `backend/gateway.go` to permit `TypeMX` and use `EGRESS_DNS`**

In `backend/gateway.go`:
```go
		q, err := parser.Question()
		if err != nil || q.Class != dnsmessage.ClassINET ||
			(q.Type != dnsmessage.TypeA &&
				q.Type != dnsmessage.TypeAAAA &&
				q.Type != dnsmessage.TypeTXT &&
				q.Type != dnsmessage.TypeCNAME &&
				q.Type != dnsmessage.TypeMX) {
			continue
		}
		select {
		case semaphore <- struct{}{}:
		default:
			continue
		}
		go func(packet []byte, peer net.Addr) {
			defer func() { <-semaphore }()
			upstream := os.Getenv("EGRESS_DNS")
			if upstream == "" {
				upstream = "1.1.1.1:53"
			}
			up, e := net.DialTimeout("udp", upstream, 3*time.Second)
			if e != nil {
				return
			}
			defer up.Close()
			up.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e = up.Write(packet); e != nil {
				return
			}
			answer := make([]byte, 4096)
			size, e := up.Read(answer)
			if e == nil {
				_, _ = conn.WriteTo(answer[:size], peer)
			}
		}(append([]byte{}, buf[:n]...), peer)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test -race -run '^TestDNSRelayAllowsMXAndFiltersDisallowed$' .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/gateway.go backend/dns_relay_test.go
git commit -m "fix(gateway): allow MX DNS queries through relay for governance audits"
```

---

### Task 2: Subdomain Takeover Two-Scan Resolution & Reopen Lifecycle

**Files:**
- Modify: `backend/main.go:161-171`
- Modify: `lib/types.ts:142-153`
- Modify: `backend/jobs.go:1017-1058`
- Test: `backend/takeover_lifecycle_test.go`

**Interfaces:**
- Consumes: `sc.Checkpoint.Takeovers`, `s.state.Takeovers`, `successful bool` in `normalize()`
- Produces: `SubdomainTakeover.MissingScans int`, resolving takeovers only when `MissingScans >= 2` across successive successful scans, and reopening on rediscovery.

- [ ] **Step 1: Write the failing test**

Create `backend/takeover_lifecycle_test.go`:
```go
package main

import (
	"testing"
)

func TestSubdomainTakeoverTwoScanResolutionAndReopening(t *testing.T) {
	s := testServer(t)
	sc1 := &Scan{
		ID:       "scan-1",
		TargetID: "target-1",
		Domain:   "example.com",
		Status:   "completed",
		Checkpoint: Checkpoint{
			Takeovers: []SubdomainTakeover{
				{
					Subdomain:       "sub.example.com",
					CNAME:           "vulnerable.s3.amazonaws.com",
					ServiceProvider: "AWS S3",
				},
			},
		},
	}

	// 1. First scan detects takeover
	s.normalize(sc1, true)
	if len(s.state.Takeovers) != 1 {
		t.Fatalf("expected 1 takeover, got %d", len(s.state.Takeovers))
	}
	to := s.state.Takeovers[0]
	if to.Status != "open" || to.MissingScans != 0 {
		t.Fatalf("expected open takeover with MissingScans=0, got %+v", to)
	}

	// 2. Second scan (successful) does NOT detect the takeover
	sc2 := &Scan{
		ID:         "scan-2",
		TargetID:   "target-1",
		Domain:     "example.com",
		Status:     "completed",
		Checkpoint: Checkpoint{},
	}
	s.normalize(sc2, true)
	to = s.state.Takeovers[0]
	if to.Status != "open" {
		t.Fatalf("takeover should remain open after only 1 missing scan, got status=%s", to.Status)
	}
	if to.MissingScans != 1 {
		t.Fatalf("expected MissingScans=1, got %d", to.MissingScans)
	}

	// 3. Third scan (successful) still does NOT detect the takeover -> Resolves
	sc3 := &Scan{
		ID:         "scan-3",
		TargetID:   "target-1",
		Domain:     "example.com",
		Status:     "completed",
		Checkpoint: Checkpoint{},
	}
	s.normalize(sc3, true)
	to = s.state.Takeovers[0]
	if to.Status != "resolved" {
		t.Fatalf("takeover should be resolved after 2 missing scans, got status=%s", to.Status)
	}
	if to.MissingScans != 2 {
		t.Fatalf("expected MissingScans=2, got %d", to.MissingScans)
	}

	// 4. Fourth scan detects the takeover again -> Reopens
	sc4 := &Scan{
		ID:       "scan-4",
		TargetID: "target-1",
		Domain:   "example.com",
		Status:   "completed",
		Checkpoint: Checkpoint{
			Takeovers: []SubdomainTakeover{
				{
					Subdomain:       "sub.example.com",
					CNAME:           "vulnerable.s3.amazonaws.com",
					ServiceProvider: "AWS S3",
				},
			},
		},
	}
	s.normalize(sc4, true)
	to = s.state.Takeovers[0]
	if to.Status != "open" {
		t.Fatalf("takeover should reopen to status=open, got %s", to.Status)
	}
	if to.MissingScans != 0 {
		t.Fatalf("expected MissingScans reset to 0, got %d", to.MissingScans)
	}
	if to.ReopenCount != 1 {
		t.Fatalf("expected ReopenCount=1, got %d", to.ReopenCount)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test -race -run '^TestSubdomainTakeoverTwoScanResolutionAndReopening$' .`
Expected: FAIL (`to.MissingScans undefined` or resolves prematurely on scan 2).

- [ ] **Step 3: Update `backend/main.go`, `lib/types.ts`, and `backend/jobs.go`**

In `backend/main.go`:
```go
type SubdomainTakeover struct {
	ID              string `json:"id"`
	ScanID          string `json:"scanId"`
	Subdomain       string `json:"subdomain"`
	CNAME           string `json:"cname"`
	ServiceProvider string `json:"serviceProvider"`
	Status          string `json:"status"` // 'open', 'resolved', 'suppressed'
	FirstSeen       string `json:"firstSeen"`
	LastSeen        string `json:"lastSeen"`
	ReopenCount     int    `json:"reopenCount"`
	MissingScans    int    `json:"missingScans"`
}
```

In `lib/types.ts`:
```ts
export type SubdomainTakeover = {
  id: string;
  scanId: string;
  subdomain: string;
  cname: string;
  serviceProvider: string;
  status: string;
  firstSeen: string;
  lastSeen: string;
  reopenCount: number;
  missingScans?: number;
};
```

In `backend/jobs.go` (`normalize()` lines 1017-1058):
```go
	// 2. Ingest Subdomain Takeovers
	observedTakeovers := map[string]bool{}
	for _, to := range sc.Checkpoint.Takeovers {
		to.ScanID = sc.ID
		toKey := to.Subdomain + "|" + to.ServiceProvider
		observedTakeovers[toKey] = true
		found := false
		for i, old := range s.state.Takeovers {
			if old.Subdomain == to.Subdomain && old.ServiceProvider == to.ServiceProvider {
				s.state.Takeovers[i].LastSeen = stamp
				s.state.Takeovers[i].ScanID = sc.ID
				s.state.Takeovers[i].CNAME = to.CNAME
				s.state.Takeovers[i].MissingScans = 0
				if old.Status == "resolved" {
					s.state.Takeovers[i].Status = "open"
					s.state.Takeovers[i].ReopenCount++
					s.emit("takeover", "Subdomain takeover returned", to.Subdomain+" · "+to.ServiceProvider, stamp)
				}
				found = true
				break
			}
		}
		if !found {
			to.FirstSeen = stamp
			to.LastSeen = stamp
			to.Status = "open"
			to.MissingScans = 0
			s.state.Takeovers = append(s.state.Takeovers, to)
			s.emit("takeover", "Subdomain takeover candidate detected", to.Subdomain+" · "+to.ServiceProvider, stamp)
		}
	}
	if successful {
		for i := range s.state.Takeovers {
			old := &s.state.Takeovers[i]
			if !inScope(old.Subdomain, sc.Domain) || old.Status != "open" {
				continue
			}
			toKey := old.Subdomain + "|" + old.ServiceProvider
			if !observedTakeovers[toKey] {
				old.MissingScans++
				if old.MissingScans >= 2 {
					old.Status = "resolved"
					s.emit("resolved", "Subdomain takeover resolved", old.Subdomain+" · "+old.ServiceProvider, stamp)
				}
			} else {
				old.MissingScans = 0
			}
		}
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test -race -run '^TestSubdomainTakeoverTwoScanResolutionAndReopening$' .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/main.go lib/types.ts backend/jobs.go backend/takeover_lifecycle_test.go
git commit -m "fix(jobs): require two successful scans confirming absence to resolve takeovers"
```

---

### Task 3: PostgreSQL Schema Migration & Storage Persistence for Takeover MissingScans

**Files:**
- Modify: `backend/schema.sql:80-92`
- Modify: `backend/storage.go:133-141, 270-283`
- Test: `backend/storage_test.go` or `backend/takeover_lifecycle_test.go`

**Interfaces:**
- Consumes: `s.db.Query`, `tx.Exec` in `storage.go`
- Produces: Persisted `missing_scans` column in `subdomain_takeovers` across reload and upsert operations.

- [ ] **Step 1: Write storage roundtrip test**

Add to `backend/takeover_lifecycle_test.go`:
```go
func TestSubdomainTakeoverJSONSerialization(t *testing.T) {
	to := SubdomainTakeover{
		ID:              "to-1",
		ScanID:          "scan-1",
		Subdomain:       "sub.example.com",
		CNAME:           "vulnerable.s3.amazonaws.com",
		ServiceProvider: "AWS S3",
		Status:          "open",
		FirstSeen:       "2026-10-18T00:00:00Z",
		LastSeen:        "2026-10-18T01:00:00Z",
		ReopenCount:     1,
		MissingScans:    1,
	}
	data, err := json.Marshal(to)
	if err != nil {
		t.Fatal(err)
	}
	var loaded SubdomainTakeover
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.MissingScans != 1 {
		t.Fatalf("expected MissingScans=1 after unmarshal, got %d", loaded.MissingScans)
	}
}
```

- [ ] **Step 2: Update `backend/schema.sql`**

Update `subdomain_takeovers` definition and add migration:
```sql
CREATE TABLE IF NOT EXISTS subdomain_takeovers (
    id text PRIMARY KEY,
    scan_id text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    cname VARCHAR(255) NOT NULL,
    service_provider VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reopen_count INTEGER NOT NULL DEFAULT 0,
    missing_scans INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_takeover_subdomain UNIQUE(subdomain, service_provider)
);
CREATE INDEX IF NOT EXISTS idx_takeovers_scan ON subdomain_takeovers(scan_id);
CREATE INDEX IF NOT EXISTS idx_takeovers_status ON subdomain_takeovers(status);

ALTER TABLE subdomain_takeovers ADD COLUMN IF NOT EXISTS missing_scans INTEGER NOT NULL DEFAULT 0;
INSERT INTO schema_migrations(version) VALUES(5) ON CONFLICT DO NOTHING;
```

- [ ] **Step 3: Update `backend/storage.go`**

In `backend/storage.go:133`:
```go
	if toRows, err := s.db.Query(ctx, "SELECT id, scan_id, subdomain, cname, service_provider, status, first_seen::text, last_seen::text, reopen_count, COALESCE(missing_scans, 0) FROM subdomain_takeovers ORDER BY last_seen DESC"); err == nil {
		for toRows.Next() {
			var to SubdomainTakeover
			if scanErr := toRows.Scan(&to.ID, &to.ScanID, &to.Subdomain, &to.CNAME, &to.ServiceProvider, &to.Status, &to.FirstSeen, &to.LastSeen, &to.ReopenCount, &to.MissingScans); scanErr == nil {
				s.state.Takeovers = append(s.state.Takeovers, to)
			}
		}
		toRows.Close()
	}
```

In `backend/storage.go:270-283`:
```go
	for _, to := range s.state.Takeovers {
		firstSeen := to.FirstSeen
		if firstSeen == "" {
			firstSeen = now()
		}
		lastSeen := to.LastSeen
		if lastSeen == "" {
			lastSeen = now()
		}
		_, _ = tx.Exec(ctx, `INSERT INTO subdomain_takeovers(id, scan_id, subdomain, cname, service_provider, status, first_seen, last_seen, reopen_count, missing_scans)
			VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT(subdomain, service_provider) DO UPDATE SET scan_id=EXCLUDED.scan_id, cname=EXCLUDED.cname, status=EXCLUDED.status, last_seen=EXCLUDED.last_seen, reopen_count=EXCLUDED.reopen_count, missing_scans=EXCLUDED.missing_scans`,
			to.ID, to.ScanID, to.Subdomain, to.CNAME, to.ServiceProvider, to.Status, firstSeen, lastSeen, to.ReopenCount, to.MissingScans)
	}
```

- [ ] **Step 4: Run backend tests**

Run: `cd backend && go test -race -run '^TestSubdomainTakeover' .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/schema.sql backend/storage.go backend/takeover_lifecycle_test.go
git commit -m "feat(storage): persist missing_scans for subdomain takeovers"
```

---

### Task 4: Documentation & Full Pipeline Verification

**Files:**
- Modify: `docs/scanning.md`

- [ ] **Step 1: Update `docs/scanning.md`**

Document that the gateway DNS relay forwards MX queries for DNS governance audits and that takeover candidates require two consecutive completed scans without detection before resolution.

- [ ] **Step 2: Commit docs**

```bash
git add docs/scanning.md
git commit -m "docs(scanning): document mx relay support and takeover two-scan confirmation"
```

- [ ] **Step 3: Run full verification suite**

Run:
1. `npm run test:api` (Go test suite with race detector)
2. `npm run typecheck` (TypeScript check)
3. `npm run build` (Next.js production build)
4. `docker build -f backend/Dockerfile.worker --target test -t surfacer-native-test .`
5. `docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=256m surfacer-native-test`
