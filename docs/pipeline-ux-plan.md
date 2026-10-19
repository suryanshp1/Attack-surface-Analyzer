# Pipeline and UX implementation plan

## Intended result

Operators can see what completed, which services remain unchecked, why, and what continuing a scan will repeat. Existing scope, pacing, authorization, lifecycle, and history remain authoritative.

## Implementation

1. Record bounded, validated HTTP outcomes by origin and required detection templates. Preserve partial observations and subprocess errors, including failed or silent sibling services. Keep healthy services eligible and shared gateway cooldowns effective.
2. Project additive public stage outcomes and coverage counts, with unknown states for older snapshots. Derive recovery previews from the same helper used by retry; retain parent-run lineage and stage timings in existing JSON storage.
3. Show warnings and coverage before technical logs, recovery details before continuation, compact paginated history, target counts instead of readiness percentages, security-issue counts separate from observations, and scan preflight availability.
4. Add bounded SSE reconnect with fallback polling, serialized refreshes, protection against superseded polling responses, hidden-tab handling, and connection freshness.
5. Validate backend behavior with deterministic regressions and race detection, types and production build, isolated native scanner fixture, isolated UI fixtures in both appearances and at desktop/mobile widths. Update API and scanning docs.

## Review correction

The original audit conflated `Checkpoint.Blocked` with `Asset.Blocked`. Detection already excludes individual failing services; it does not skip healthy siblings merely because the host appears in `Checkpoint.Blocked`. The implementation strengthens per-origin accounting and prevents missing/failed sibling responses from appearing covered.

## Follow-on measurements

Keep configured scanner budgets and topology. Changes to scheduling, concurrency, full-state transport, and percentile telemetry require representative workload measurements; these are follow-on optimization work rather than assumed speed improvements.

## Implemented and validated

- Per-origin HTTP outcomes, subprocess-error preservation, required detection counts, stage warnings and timings, shared retry preview, parent linkage and correct resumed stage progress.
- Compact URL-paginated history, security issue/observation separation, readiness target counts, preflight and viewer-aware continuation controls.
- Serialized, timeout-bounded snapshot refreshes; SSE reconnect, fallback polling, hidden-tab suspension and visible freshness.
- Backend race suite, eight deterministic client-sync tests, TypeScript and production build passed. The native Linux scanner fixture passed with networking disabled. The PostgreSQL/MinIO integration passed on a fresh private network using temporary storage and a restricted application role; lineage, timings and coverage fields round-trip through JSONB. The JSON-backed store is covered by the retry regression tests.
- Isolated browser fixtures checked desktop/mobile in light/dark appearances, 390px horizontal overflow, continuation detail, pagination/filter URL state, and Escape focus restoration.

No existing workspace was scanned, seeded, reset, or deployed as part of validation.
