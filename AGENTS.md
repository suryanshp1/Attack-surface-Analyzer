# Development guidelines for Surfacer

These instructions apply across this repository. Surfacer is a self-hosted, domain-scoped external attack surface application built with Next.js, React, Tailwind CSS, Go, PostgreSQL, MinIO, and pinned open-source scanners.

Treat source code, tests, and `compose.yaml` as authoritative for current behavior. `PRD.md` and `design.md` provide product intent; they do not establish that a feature is implemented. Keep changes focused, preserve existing work, and read the relevant subsystem before editing.

<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

## Project architecture

```text
app/                  Next.js App Router, session endpoint, backend API proxy
components/           Workspace UI and appearance controls
lib/                  Shared types, URL state, and appearance bootstrap
backend/              Go API, scheduler, worker, gateway, persistence, and tests
backend/templates/    Curated signed Nuclei templates, license, and manifest
scripts/              Setup, development launchers, scanner fetch, backup, tests
deploy/               Pinned MinIO source image build
public/openapi.json   Public API route and role reference
docs/                 Architecture, operations, scanning, development, media
compose.yaml          Complete deployment and network boundaries
```

- **UI and proxy:** `app/`, `components/`, and `lib/`. Browser requests use the Next.js session and server-side API proxy; service credentials must stay on the server.
- **API and coordination:** `backend/main.go`, `access.go`, and `jobs.go` handle authorization, scope, schedules, durable scans, leases, and events.
- **Scanner execution:** `backend/worker.go`, `advanced_scanners.go`, and `crawl.go` run tools, normalize observations, and preserve checkpoints.
- **Egress:** `backend/gateway.go`, `tcp_gateway.go`, and `traffic.go` enforce destination scope, active authorization, and pacing.
- **Persistence:** `backend/storage.go` and `schema.sql` maintain PostgreSQL state and S3-compatible evidence. Reports and metrics live in `reports.go` and `metrics.go`.

The supported Compose topology is one workspace and one API process with scalable workers. Only the web port is published, bound to loopback by default. Workers use an internal network, reach targets through the gateway, and commit results through the API; they have no database or S3 credentials. Preserve those boundaries.

## Development tools and commands

Run commands from the repository root unless explicitly shown otherwise. Use Node.js 22+, npm with `package-lock.json`, and Go 1.25+ for local backend work. Docker Engine with Compose v2 runs the complete stack.

```sh
# Local UI and loopback JSON-backed API; no live scanner workers
npm ci
node scripts/setup.mjs
npm run dev

# Complete stack with PostgreSQL, evidence storage, gateway, and scanners
docker compose up -d --build

# Health and diagnostics
docker compose ps
docker compose logs --tail=50 worker api gateway
```

Local development stores data in `backend/data/workspace.json`; Compose uses separate durable volumes. Do not confuse the two environments or populate a live workspace with fixtures. Check which services already own the ports before starting another stack. Setup generates credentials in `.env` while preserving existing values; never print or commit those credentials.

### Dependencies and configuration

- Use npm for frontend dependencies and Go modules for backend dependencies. Keep their manifests and lockfiles consistent; do not introduce a second package manager.
- Add dependencies only when needed for the task and explain their purpose. Avoid unrelated upgrades or lockfile churn.
- Frontend behavior is configured by `package.json`, `tsconfig.json`, and `next.config.ts`; Go dependencies by `backend/go.mod` and `go.sum`; runtime topology by `compose.yaml` and Dockerfiles.
- Keep scanner versions pinned in `scripts/fetch-scanners.py` and consistent with runtime version checks and the README. Preserve published checksum verification and upstream license retrieval.
- Do not edit installed dependencies, generated Next.js output, or test artifacts as a substitute for a source fix. Preserve the generated Next.js instructions above.

## Compatibility and data integrity

Before changing a public API or stored representation, inspect its handlers, frontend consumers in `lib/types.ts`, proxy behavior, tests, and `public/openapi.json`. Prefer additive changes; explain unavoidable compatibility changes and update callers and docs together.

Preserve persisted workspace data, finding fingerprints, first-seen timestamps, triage notes, scan history, and durable checkpoints. Schema changes must work with the existing migration path and restricted application role; do not reset databases or volumes to make a migration pass. Consider both the JSON-backed development store and PostgreSQL when changing shared state.

Changes to scan stages or checkpoints must account for interrupted runs and previously saved stage layouts. Reject stale leases and duplicate/concurrent target runs. Keep retries bounded and resumable rather than silently repeating all completed work.

## Code quality

- Follow the surrounding code's conventions. Use descriptive names and focused functions; avoid unrelated refactors and speculative abstractions.
- Keep TypeScript strict and shared types accurate. Validate untrusted input at API boundaries instead of trusting frontend controls or type assertions.
- Format changed Go files with `gofmt`. Propagate contextual errors and use contexts for subprocesses, network requests, and cancellation.
- Close response bodies, files, database resources, and sockets. Bound scanner output, memory use, concurrency, and runtime. Preserve process-group cleanup on cancellation.
- Keep Python and Node utility scripts explicit about inputs, errors, and cleanup. Never build shell commands by interpolating user-controlled values or secrets; pass argument arrays where possible.
- Document non-obvious invariants and tradeoffs. Avoid comments that merely repeat the code, broad error suppression, and dead code.

## Scanning and security invariants

These are product behavior, not optional test conveniences:

- Active destinations must remain public and within the selected root domain/subdomains. Preserve dial-time DNS checks, redirect checks, private/rebinding protections, signed permits, and lease validation.
- DNS ownership verification is optional by default and configurable with `REQUIRE_DNS_VERIFICATION`. Optional mode must not mark targets verified; required mode must enforce ownership loss and cancellation.
- Keep workspace kill-switch, paused-target, role, and revocation checks effective across API calls, worker execution, gateway tunnels, and event streams.
- Scanner traffic must use the authorized gateway path. Do not add a direct-internet fallback, host networking, Docker socket access, or production private-IP bypass to fix a failing scan.
- Respect rate limits, bounded concurrency, `Retry-After`, and cooldowns. User-Agent variants identify Surfacer. Do not introduce browser impersonation, WAF bypass, credential guessing, or unsolicited intrusive checks.
- Keep evidence redacted, size-capped, and rendered as inert text. Never persist raw discovered secrets, validate them against third-party services, or send evidence to external AI services without an explicitly authorized feature change.
- Maintain server-side authorization and secret handling. Never expose service tokens in browser bundles, URLs, screenshots, logs, issue reports, or committed files. Preserve append-only audit records.

### Coverage and lifecycle

A partial scan is useful observation data, not proof of a clean assessment. Preserve completed scanner output and explicitly identify blocked, failed, excluded, or unfinished checks.

- Findings resolve only after two successful scans with explicit host/template coverage.
- Assets are removed only after two successful scans confirming DNS absence.
- Endpoints are removed only after two clean completed crawls establishing absence.
- Missing responses, DNS failures, skipped templates, and partial scans must retain unchecked history. Preserve accepted-risk/false-positive decisions and reopen resolved findings when rediscovered.
- Historical URLs remain labeled unverified. Do not present archive entries as live services or stage completion as a percentage of asset coverage.

### Scanner and template updates

Review request behavior, resource budgets, version compatibility, attribution, and licenses. Keep Nuclei signatures valid and update source URLs, hashes, and technology gates in `backend/templates/manifest.json`. Do not enable the entire upstream catalog by default. Use an isolated real-scanner fixture to validate scanner/template changes; test-only DNS/dial injection must remain outside the production binary.

## UI and UX

Use the existing Tailwind v4 tokens and shared styles in `app/globals.css`. Preserve light, dark, and system appearance, including initialization before hydration and browser-local preference persistence. Do not create a competing theme system or hardcode colors that break one palette.

Keep scope, filters, pagination, and entity details consistent with `lib/workspace-route.ts` and browser Back/refresh behavior. Distinguish scan readiness from assessment completeness. Use explicit loading, empty, partial, unavailable, and error states; never replace missing backend data with fabricated metrics or findings.

Preserve keyboard access, visible focus, semantic control labels, dialog focus management, readable contrast, mobile layouts, and usable touch targets. Check UI changes in both appearances and at desktop/mobile widths. Use real observations or isolated fixtures for screenshots; do not seed production data for presentation.

## Validation

Choose checks that prove the changed behavior. For behavior-changing backend work, add a deterministic regression test covering the failure and relevant edge cases. Avoid implementation-mirroring tests or tests solely for static copy/style changes.

```sh
# Frontend types and production build
npm run typecheck
npm run build

# Backend unit/regression suite with race detection
npm run test:api

# Focused backend test, from backend/
cd backend
go test -race -run '^TestName$' .
```

Use local fixtures or mocks for external dependencies. Unit tests must not scan real targets or require live provider services. Ordinary Go tests skip native scanner/storage integration unless their dedicated environment is enabled; skipped tests are not integration passes.

For scanner execution, gateway, or template changes, run the real Linux scanner fixture from the repository root:

```sh
docker build -f backend/Dockerfile.worker --target test -t surfacer-native-test .
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,size=256m surfacer-native-test
```

Storage changes should also exercise `TestStorageIntegration` against disposable PostgreSQL/S3 resources. `scripts/test-storage.py` assumes the default Compose network name and creates/drops `surfacer_test`; use a dedicated development stack and inspect the helper before running it. Never aim integration tests at live workspace storage.

For docs-only changes, validate local links, commands, and Mermaid syntax as relevant. Run applicable checks once, then repeat only for new changes or unresolved failures. Report what passed, what skipped, and any concrete limitations; do not claim a production deployment or full remote scan completed from unit tests or a local fixture.

## Git, pull requests, and documentation

Preserve unrelated working-tree edits. Do not discard user changes or run destructive cleanup to obtain a clean tree. Keep generated output, `.env`, authentication state, dumps, and unredacted evidence out of commits.

Use concise Conventional Commit-style titles where practical, with scopes such as `web`, `api`, `worker`, `gateway`, `storage`, `scanners`, or `docs`. Example: `fix(worker): retain crawl results after timeout`. There is no prescribed username-based branch format or automated release workflow; do not invent one or publish a release as part of routine validation.

PR descriptions should lead with the problem and resulting behavior, explain compatibility/migration impacts, and state relevant validation. Include screenshots for UI changes and careful-review notes for scope, authorization, lifecycle, or persistence changes. Follow [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Keep the README focused on onboarding, implemented features, architecture, and limits. Put operational detail in `docs/`; avoid dated debugging transcripts and unsupported production claims. Update `public/openapi.json` when public routes or roles change. Keep diagrams aligned with `compose.yaml` and include upstream notices when adding bundled components. Surfacer's own code is Apache-2.0; third-party components retain their licenses.

## Further context

- [README](README.md): quick start, preview, scanner versions, current limits.
- [Architecture](docs/architecture.md): service topology, scan flow, trust boundaries.
- [Scanning and coverage](docs/scanning.md): profiles, budgets, recovery, lifecycle.
- [Operations](docs/operations.md): deployment, configuration, access, backup, troubleshooting.
- [Development](docs/development.md): local setup and detailed validation guidance.
- [Third-party notices](THIRD_PARTY_NOTICES.md): bundled components and license locations.
