# Pipeline Concurrency & Timeout Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate rigid timeouts and bottlenecked serial stages across the Surfacer scanning engine, introducing worker-pool concurrency, dual-stack fast-fallback dialing, and asynchronous stage pipelining.

**Architecture:** Refactor the gateway dialer with IPv4-first fast fallback (sub-dial bounding), parallelize intra-stage operations (`inspectCertificates`, `analyzeJavaScript`, `resolve`, and `crawlSeeds`) using bounded worker pools bounded by `Scan.Concurrency` and `Scan.Rate`, and decouple independent stages (`Historical discovery` and `TLS assessment` concurrent with `HTTP probing`).

**Tech Stack:** Go 1.25, `golang.org/x/sync/errgroup`, standard library concurrency (`sync.WaitGroup`, buffered channels), Context propagation, PostgreSQL, MinIO.

## Global Constraints
- Preserve scanner authorization permits, lease checks, and egress proxy routing (zero direct internet egress from workers).
- Do not exceed configured workspace rates (`Scan.Rate`) or concurrency budgets (`Scan.Concurrency`).
- Incomplete coverage and blocked destination tracking must remain deterministic.
- All Go code must pass `npm run test:api` (`go test -race ./...`) without data races.
- Frontend types and build must remain clean (`npm run typecheck`, `npm run build`).

---

### Task 1: Gateway Resilient Dialing & Timeout Elimination

**Files:**
- Modify: `backend/gateway.go:62-95`
- Test: `backend/runtime_test.go`

**Interfaces:**
- Consumes: `g.safeDial(ctx, network, address)`, `pinnedResolver().LookupNetIP(ctx, "ip", host)`
- Produces: `net.Conn` with fast fallback (IPv4-first, 3s bounded per-IP dial), preventing upstream context cancellation.

- [x] **Step 1: Write the failing regression test for dual-stack fallback**
Add a test in `backend/runtime_test.go` verifying that when a host resolves to an unroutable IP followed by a working loopback/mock IP, `resolveDial` succeeds within 4 seconds without exhausting the parent deadline.

- [x] **Step 2: Run test to verify it fails**
Run: `cd backend && go test -race -run '^TestGatewayDualStackFallback$' .`
Expected: FAIL (dial hangs or times out).

- [x] **Step 3: Implement IPv4 priority & per-IP sub-dial timeouts in `backend/gateway.go`**
Sort public IPs IPv4-first and wrap each dial attempt in a sub-context bounded to `3 * time.Second`.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestGatewayDualStackFallback$' .`
Expected: PASS.

- [x] **Step 5: Run full test suite**
Run: `npm run test:api`

---

### Task 2: Intra-Stage Concurrency for Certificate Inspection & DNS

**Files:**
- Modify: `backend/worker.go:458-480` (`resolve` fallback loop)
- Modify: `backend/worker.go:653-696` (`inspectCertificates`)
- Test: `backend/ui_state_test.go` or `backend/coverage_test.go`

**Interfaces:**
- Consumes: `cp.Assets`, `sc.Rate`, `sc.Concurrency`
- Produces: Concurrently inspected TLS certificates and concurrently resolved DNS records with rate limiter protection.

- [x] **Step 1: Write unit tests for concurrent certificate inspection and DNS fallback**
Write test asserting that 20 mock assets are inspected in parallel within 2 seconds instead of taking 10+ seconds serially.

- [x] **Step 2: Run test to verify it fails**
Run: `cd backend && go test -race -run '^TestConcurrentInspectCertificates$' .`
Expected: FAIL.

- [x] **Step 3: Implement bounded worker pool in `inspectCertificates` and `resolve`**
Use `sync.WaitGroup` and a worker pool sized to `max(2, min(c.Scan.Concurrency, 10))` with thread-safe slice/map appends protected by a mutex.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestConcurrentInspectCertificates$' .`
Expected: PASS.

- [x] **Step 5: Run full test suite**
Run: `npm run test:api`

---

### Task 3: Concurrent Endpoint Crawling & Dynamic Timeout Budgeting

**Files:**
- Modify: `backend/crawl.go:90-170`
- Test: `backend/crawl_test.go`

**Interfaces:**
- Consumes: `crawlSeeds(cp)`, `c.Scan.Concurrency`
- Produces: Multi-worker crawl execution with progressive checkpoint commits and dynamic deadlines.

- [x] **Step 1: Write test for multi-worker crawl seed processing**
Add test verifying that multiple seeds are dispatched concurrently up to worker concurrency limit without blocking serially for 110s each.

- [x] **Step 2: Run test to verify it fails**
Run: `cd backend && go test -race -run '^TestConcurrentCrawlSeeds$' .`
Expected: FAIL.

- [x] **Step 3: Implement concurrent seed dispatcher in `backend/crawl.go`**
Spawn worker pool of size `min(len(seeds), c.Scan.Concurrency)`. Mutex-guard `cp.CrawlResults`, `cp.CrawlIncomplete`, and `cp.Assets`.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestConcurrentCrawlSeeds$' .`
Expected: PASS.

- [x] **Step 5: Run full test suite**
Run: `npm run test:api`

---

### Task 4: Concurrent JavaScript Secret Fetching

**Files:**
- Modify: `backend/crawl.go:295-365` (`analyzeJavaScript`)
- Test: `backend/crawl_test.go`

**Interfaces:**
- Consumes: `cp.Assets[*].Endpoints` (JavaScript files)
- Produces: Parallel downloaded scripts via worker pool into `jsDir`, followed by a single consolidated `gitleaks` pass.

- [x] **Step 1: Write test for parallel JS download**
Test verifying that 30 JS endpoints download concurrently within rate limit constraints without serialized ticker delays.

- [x] **Step 2: Run test to verify it fails**
Run: `cd backend && go test -race -run '^TestParallelJavaScriptDownload$' .`
Expected: FAIL.

- [x] **Step 3: Implement worker pool in `analyzeJavaScript`**
Use a worker channel pool of 5 workers reading from a shared jobs channel, governed by token bucket rate limiter.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestParallelJavaScriptDownload$' .`
Expected: PASS.

- [x] **Step 5: Run full test suite**
Run: `npm run test:api`

---

### Task 5: Decoupled Stage Concurrency (DAG Execution)

**Files:**
- Modify: `backend/worker.go:230-318` (`execute`)
- Test: `backend/native_test.go` or `backend/coverage_test.go`

**Interfaces:**
- Consumes: Scan stages slice
- Produces: Asynchronous parallel execution of independent stages (`Historical discovery` parallelized with `Port discovery` & `HTTP probing`; `TLS assessment` parallelized with `HTTP probing`).

- [x] **Step 1: Add DAG dependency checks in worker pipeline**
Define stage dependencies explicitly:
- `Discovery` -> `DNS resolution`
- `DNS resolution` -> `Port discovery` AND `Historical discovery` (parallel)
- `Port discovery` -> `HTTP probing` AND `TLS assessment` (parallel)
- `HTTP probing` -> `TLS inspection` AND `Endpoint crawling` (parallel)
- `Endpoint crawling` -> `JavaScript secrets` AND `Detection` (parallel)
- All complete -> `Normalization` -> `Change detection`

- [x] **Step 2: Implement concurrent stage runner with error propagation**
Run independent stage pairs via `errgroup.Group`, updating checkpoint atomically under mutex.

- [x] **Step 3: Verify all unit and integration tests**
Run: `npm run test:api && npm run typecheck`
Ensure zero race conditions (`-race`) and clean completion.
