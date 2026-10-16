# Resilient Scan Pipeline & Graceful Stage Continuation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent scanner or target failures from aborting the scan pipeline, ensuring all 12 stages run to completion with per-check isolation, non-blocking fault handling, and clear coverage transparency.

**Architecture:** Wrap all intra-stage scanner invocations (`naabu`, `tlsx`, `httpx`, `katana`, `nuclei`, `gitleaks`) in resilient fallback harnesses that log failures to `cp.SourceIssues`, mark affected targets in `cp.Blocked`/`cp.PortIncomplete`/`cp.CrawlIncomplete`, and continue processing remaining targets and subsequent stages. Update `worker.go` stage loop to never abort early on non-fatal stage errors, allowing downstream stages (including Detection and Normalization) to evaluate all responsive assets. Enhance UI messaging to clearly distinguish between completed pipeline execution and partial host coverage.

**Tech Stack:** Go 1.25, TypeScript / React / Next.js 15, Context cancellation & deadline propagation, PostgreSQL JSONB storage, Tailwind CSS v4.

## Global Constraints
- Preserve scanner authorization permits, lease checks, and egress proxy routing (zero direct internet egress from workers).
- Retain Surfacer coverage invariants: partial scans retain existing findings and unchecked history; hosts are never marked clean without verified checks.
- Do not bypass rate limits (`Scan.Rate`) or concurrency limits (`Scan.Concurrency`).
- All Go tests must pass with `-race` (`npm run test:api`).
- Frontend typecheck and build must remain clean (`npm run typecheck`, `npm run build`).

---

### Task 1: Intra-Stage Tool Error Isolation & Non-Fatal Batch Recovery

**Files:**
- Modify: `backend/advanced_scanners.go:135-155` (`scanPorts`)
- Modify: `backend/advanced_scanners.go:210-225` (`assessTLS`)
- Modify: `backend/crawl.go:185-210` (`crawlSeeds`)
- Modify: `backend/worker.go:575-595` (`probe`)
- Modify: `backend/worker.go:945-960` (`detect`)
- Test: `backend/worker_test.go` or `backend/runtime_test.go`

**Interfaces:**
- Consumes: `command(ctx, tool, args, proxy, dir)`
- Produces: `Checkpoint` with `cp.SourceIssues` appended on tool/batch errors, affected hosts marked in `cp.Blocked` or incomplete lists, and `error == nil` to allow stage to finish.

- [x] **Step 1: Write regression test for non-fatal batch failure in `scanPorts` and `probe`**
Write a unit test in `backend/worker_test.go` (or `backend/runtime_test.go`) simulating a command runner that returns an exit error for one batch of targets but succeeds for another, asserting that the function retains findings from successful batches, logs the failure in `cp.SourceIssues`, and returns `err == nil`.

- [x] **Step 2: Run test to verify it fails**
Run: `cd backend && go test -race -run '^TestNonFatalToolFailure$' .`
Expected: FAIL (currently returns `runErr` and stops).

- [x] **Step 3: Implement non-fatal error isolation across scanner functions**
- In `scanPorts` (`backend/advanced_scanners.go`): if a naabu batch fails with non-deadline error, record issue in `cp.SourceIssues`, mark batch hosts in `cp.PortIncomplete`, and continue next batch.
- In `assessTLS` (`backend/advanced_scanners.go`): if `tlsx` command fails, log issue in `cp.SourceIssues` and return nil error with warning logs.
- In `crawlSeeds` (`backend/crawl.go`): if Katana fails on a single seed, do not set `fatalErr` unless `ctx.Err() != nil`; mark seed incomplete and continue other seeds.
- In `probe` (`backend/worker.go`): if `httpx` returns a non-deadline exit error, log issue in `cp.SourceIssues`, record failed hosts in `cp.Blocked`, and continue with partial results.
- In `detect` (`backend/worker.go`): if nuclei fails on a batch, log issue in `cp.SourceIssues`, mark hosts as blocked, and complete the stage.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestNonFatalToolFailure$' .`
Expected: PASS.

- [x] **Step 5: Run full backend test suite**
Run: `npm run test:api`
Expected: PASS.

---

### Task 2: Worker Stage Loop Continuation & Non-Aborting Pipeline

**Files:**
- Modify: `backend/worker.go:325-345`
- Test: `backend/worker_test.go`

**Interfaces:**
- Consumes: Stage results `(cp, logs, err)`
- Produces: Stage payload committed to `/internal/stage` as `completed` with warnings or graceful fallback, continuing to stage `stage + 1` instead of exiting early.

- [x] **Step 1: Write test for worker pipeline stage continuation on stage error**
Create a test in `backend/worker_test.go` simulating a stage returning an error, asserting that `worker.Run` proceeds to invoke subsequent stages rather than returning immediately.

- [x] **Step 2: Run test to verify it fails**
Run: `cd backend && go test -race -run '^TestWorkerStageContinuation$' .`
Expected: FAIL.

- [x] **Step 3: Update worker stage loop in `backend/worker.go`**
When `err != nil`:
- Check if error is context cancellation (`ctx.Err() != nil`). If canceled by user/timeout, release and exit.
- If it is a tool or execution failure, append error to `cp.SourceIssues`, record in stage log, mark stage status as `"completed"` with issues (or `"partial"`), commit to `/internal/stage`, and **do NOT return**—allow the loop to proceed to subsequent stages.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestWorkerStageContinuation$' .`
Expected: PASS.

- [x] **Step 5: Run full test suite**
Run: `npm run test:api`
Expected: PASS.

---

### Task 3: Backend Scan Completion and Stage Accounting

**Files:**
- Modify: `backend/jobs.go:550-580`
- Test: `backend/coverage_test.go`

**Interfaces:**
- Consumes: `/internal/complete` endpoint payload
- Produces: Final scan state with `status: "completed"` or `"partial"` based on coverage, with detailed error summary and all stages accounted for.

- [x] **Step 1: Write test for scan completion when stages contain skipped checks**
Verify that `/internal/complete` successfully commits scans where all stages ran, properly setting `sc.Progress = 100` and `sc.Status = "partial"` with descriptive coverage issues rather than 409 conflict.

- [x] **Step 2: Run test to verify it fails or passes**
Run: `cd backend && go test -race -run '^TestScanCompletionWithSkippedChecks$' .`

- [x] **Step 3: Implement validation in `backend/jobs.go`**
Ensure `/internal/complete` allows stages marked completed-with-warnings, formats `coverageSummary(cp)` with exact host breakdown (e.g. "2 hosts had no HTTP response: app.veedzai.com, status.veedzai.com"), and commits findings on all healthy hosts.

- [x] **Step 4: Run test to verify it passes**
Run: `cd backend && go test -race -run '^TestScanCompletionWithSkippedChecks$' .`
Expected: PASS.

---

### Task 4: UI Transparency: Distinguish Pipeline Completion from Host Coverage

**Files:**
- Modify: `components/workspace.tsx:109-125` (`scanSummary`)
- Modify: `components/workspace.tsx:1320-1355` (`AttentionBanner`)
- Modify: `components/workspace.tsx:2660-2690` (`ScanCoverage`)
- Test: `npm run typecheck`, `npm run build`

**Interfaces:**
- Consumes: `Scan` object with `stages`, `coverage`, and `error`
- Produces: Clear, accurate UI display showing "All 12 stages finished" and identifying specific hosts that were unreachable without alarmist "Detection did not finish" or misleading failure indications.

- [x] **Step 1: Refactor `scanSummary` and attention banner in `components/workspace.tsx`**
- In `scanSummary`: when all stages completed but some hosts were unresponsive, display: `"Scan pipeline finished (all stages completed). 2 unreachable hosts skipped for HTTP checks; existing findings preserved."`
- In `ScanCoverage`: highlight which subdomains were unreachable or skipped so the operator immediately understands what happened.
- In `probeLabel`: ensure non-HTTP hosts display clear status such as "Host unresponsive to HTTP (skipped)".

- [x] **Step 2: Run frontend typecheck**
Run: `npm run typecheck`
Expected: PASS.

- [x] **Step 3: Run production frontend build**
Run: `npm run build`
Expected: PASS.

---

### Task 5: End-to-End Verification

- [x] **Step 1: Run complete backend test suite**
Run: `npm run test:api`
Expected: PASS (all tests pass without race conditions).

- [x] **Step 2: Verify in Docker / local workspace**
Ensure docker compose environment or local dev reflects graceful skip behavior and clear reporting.
