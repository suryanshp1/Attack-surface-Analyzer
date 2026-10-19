# Scan pipeline and workspace UX review

[Back to README](../README.md)

Review date: 19 October 2026. This is an assessment and proposed backlog, not an implementation claim.

## Scope and validation

Reviewed worker orchestration, budgets, checkpoints, retry handling, public scan state, event streaming, findings enrichment, scan controls, overview, scan detail, and shared styles. Current source takes precedence over documentation and screenshots.

- `npm run typecheck`: passed.
- `go test -race ./...`: passed after allowing local test-server listeners; the initial sandboxed attempt could not bind loopback.
- Native Linux scanners and PostgreSQL/S3 integration were not exercised. Their tests require dedicated opt-in environments.
- The running application at localhost:3000 showed the token login screen. Authenticated interactions and responsive/appearance behavior were not verified live. Repository overview and scan screenshots supplied visual context and may predate current edits.
- Existing uncommitted application and documentation changes were preserved. No scans were started and no workspace data was modified.

## Current pipeline

The default stage sequence in `backend/main.go` is:

Discovery → DNS resolution → Port discovery → HTTP probing → TLS assessment → TLS inspection → Historical discovery → Endpoint crawling → JavaScript secrets → Detection → Normalization → Change detection.

Historical discovery starts in the background after successful DNS resolution and joins at its listed stage. Most other stages execute serially, with bounded concurrency inside port discovery, crawling, takeover checks, JavaScript analysis, and detection.

The existing foundation is useful: gateway-only scanner egress, signed permits and lease fencing, bounded execution, checkpoint retries, incremental publication, explicit partial outcomes, and conservative lifecycle rules. Preserve these while improving visibility and throughput. There is no runtime evidence from this review that simply raising concurrency or timeouts would improve effective coverage.

## Prioritized improvements

| Priority | Observed issue | Proposed improvement | Completion evidence |
| --- | --- | --- | --- |
| P1 | `worker.go:probe` adds a host to `Checkpoint.Blocked` for a failing service response; `detect` skips the entire asset when blocked. A blocked sibling service can suppress checks on a healthy service. | Track coverage failures per service origin and reason. Preserve host/domain gateway cooldown and authorization rules independently. Healthy origins should remain eligible when permitted by shared pacing. | Deterministic multi-service fixture: a 403/429/503 origin and a healthy sibling; preserve unchecked history for the failed origin and assess the healthy one after any required cooldown. |
| P1 | Worker stages are committed as completed even when `IncompleteStages` records an error. `publicScan` removes the checkpoint, and the UI renders completed stages with checkmarks. | Add safe public stage outcome fields: execution status, coverage status, reason code, and counts. Show “Finished with gaps” in amber and place its explanation beside the stage. Preserve existing execution status for compatibility. | Partial scan identifies the affected stage without expanding a technical log; completed passes never imply complete assessment. Test public serialization and old stored scans. |
| P1 | Public coverage has only port and crawl counters. HTTP, detection, DNS, and JavaScript gaps require logs or a summary string. | Add service/template completion counts and explicit failed, unfinished, excluded, and not-applicable counts for relevant stages. Distinguish observed inputs from exhaustive coverage. | UI answers “what was checked, what remains, why?” with real denominators; no invented percentage of the entire attack surface. |
| P1 | Resume creates a new run from the earliest affected stage, resets downstream stages, and can invalidate network checkpoints. The UI gives no preview or lineage. | Show parent run, restart stage, reusable completed work, invalidated work, and remaining checks. Label it “Continue unfinished checks” with a link between runs. Compute the preview on the server using the actual retry rules. | Preview matches retry behavior for discovery/DNS, port/HTTP, crawl, and detection resumes; concurrent-target and authorization rejection remain effective. |
| P2 | One long serial stage can consume much of the 60-minute worker window; downstream stages reserve only 15 seconds each plus final commit time. | Measure time to first useful service/finding and completed required checks. Evaluate bounded port passes or fairer stage allocation before introducing a dependency graph. Keep a single checkpoint owner for any concurrent branches. | Compare workloads with identical rate, scope, and coverage requirements. A shorter run with more unchecked work does not count as improvement. |
| P2 | `Workspace` closes EventSource on its first error and keeps fetching full state every eight seconds even while streaming works. Refreshes can overlap, with no explicit freshness state. | Reconnect SSE with bounded backoff, use polling as fallback, prevent overlapping requests and stale responses, pause unnecessary polling in hidden tabs, and show last successful update plus reconnecting/stale status. | Simulated stream loss, reconnect, slow poll, logout, and out-of-order responses preserve current state and accurately report freshness. |
| P2 | `Server.stream` builds and marshals full public state under the shared lock on a one-second loop for each connection; the client also receives full polling snapshots. | Measure snapshot bytes, marshal time, lock duration, and browser render cost. Add revision-aware updates and server-side result pagination as inventory grows, retaining authorization checks on every delivery. | Large isolated fixture and multiple viewers show reduced serialization/transfer cost without delayed revocation or lost updates. |
| P2 | Findings default to all categories; open totals include host, port, endpoint, and hazard observations alongside vulnerabilities and secrets. | Present separate counts for security issues and inventory observations. Keep discovery categories available with their existing history and fingerprints. Explain that parameter hazards are candidates, not confirmed exploitation. | Operators can identify actionable security issues immediately while still accessing every recorded observation. |
| P2 | Scan history renders every scan with all twelve stages, controls, repeated tool names, and technical metadata. It has no result pagination. | Use compact history rows with domain, outcome, current/problem stage, elapsed time, observed results, and one primary action. Keep full stages and diagnostics in detail. Paginate history and preserve URL filters. | Desktop history is easier to compare; mobile actions remain reachable without horizontal page overflow; Back/refresh preserves selection. |
| P2 | Run-scan dialog lists scan-ready targets without explaining active-run conflicts, worker availability, configured budgets, or the curated assessment scope in detail. | Add a concise preflight: selected domain, active-run state, worker readiness, current rate/concurrency, bounded profile, and curated template count. Distinguish permission to scan from availability to start now. | No-worker, paused, active-target, required-verification, and empty-target states explain the next action before submission; server authorization stays authoritative. |
| P3 | `Stage` contains no timing fields. Runtime duration summaries provide sums/counts, not percentile distributions or per-run UI timings. | Add queued/claimed/stage start/finish timestamps and bounded telemetry for queue delay, partial reasons, cooldown waits, and coverage outcomes. Use histograms if percentiles are needed; avoid sensitive/high-cardinality metric labels. | Detail shows elapsed stage time and last progress; operators can distinguish slow work, waiting, and stalled updates without a fabricated ETA. |

## UX direction

Keep the existing neutral palette, appearance system, URL state, and navigation structure. The reviewed screenshots already have a coherent visual hierarchy. More decoration, animation, or a font replacement is lower value than resolving ambiguous outcomes.

Make the overview lead with actionable security issues, assessment gaps, and observation freshness. “Ready to start a scan: 100%” describes eligibility but can visually resemble assessment completion; replace the headline percentage with “2 targets ready” and show latest assessment status per target separately. In all-target scope, one recent successful scan must not imply every target is recently assessed.

In scan detail, lead with the problem and recovery action. Show the affected origins/checks and a short human-readable reason before optional technical logs. Expose independent execution and coverage outcomes rather than making users infer their difference from a disclaimer.

For a hypothetical interrupted detection run, the intended presentation is: “Detection finished with gaps” → actual completed/required service-template checks → specific unfinished origins and reason → “Continue unfinished checks.” All counts must come from backend observations. Unknown denominators should display as unknown.

Retain keyboard dialog handling, visible focus, reduced-motion support, and the existing light/dark/system preference. Validate the proposed changes at desktop and mobile widths in both appearances, including long domains, long diagnostics, empty states, stale connections, and no permission to mutate. Verify keyboard focus through expandable diagnostics and recovery actions.

## Recommended delivery order

1. Fix service-level failure scope and expose structured stage/coverage outcomes together. Update Go/TypeScript types, public API documentation, persistence compatibility, and deterministic regression tests.
2. Build the scan detail and recovery preview on those fields; simplify history and distinguish observations from security issues.
3. Repair live-update reconnect/freshness behavior and measure full-state transport costs.
4. Use the resulting timing and coverage data to tune scheduling and stage allocation. Run the isolated native scanner fixture for scanner/gateway changes and disposable storage integration for persistence changes.

The first milestone should let an operator answer: **What completed, what remains unchecked, why, and what will continuing the scan do?**
