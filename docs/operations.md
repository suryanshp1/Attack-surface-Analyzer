# Operations

[Back to README](../README.md)

## Configuration

Run `node scripts/setup.mjs` before the first Compose start. It creates `.env` with independent random credentials and preserves existing values. Do not replace generated secrets with the placeholders in `.env.example`.

| Setting | Purpose |
| --- | --- |
| `WORKSPACE_TOKEN` | Bootstrap owner sign-in |
| `API_TOKEN` | Web-to-API service authentication |
| `WORKER_TOKEN` | Worker and gateway control-plane authentication |
| `EGRESS_SECRET` | Signing scoped scan permits |
| `POSTGRES_PASSWORD` | Migration/database administrator credential |
| `POSTGRES_APP_PASSWORD` | Restricted application database credential |
| `S3_ACCESS_KEY`, `S3_SECRET_KEY` | Evidence-store credentials |
| `FRONTEND_PORT` | Host web port; default `3000` |
| `REQUIRE_DNS_VERIFICATION` | Require public ownership proof; default `false` |

Scan schedules, rate/concurrency limits, retention, and the kill switch are configured in workspace settings and captured into each new scan. Appearance is a browser-local preference, available in the header and Settings → General; System follows device appearance.

To use another local port:

```sh
FRONTEND_PORT=3002 docker compose up -d
```

The API supports `S3_ENDPOINT`, `S3_TLS`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, and `S3_BUCKET`. The supplied Compose file sets the endpoint and bucket directly; use a Compose override to point the API to external S3-compatible storage. Setting those names in `.env` alone does not override hardcoded Compose fields. Back up and migrate existing evidence before changing stores.

## Deployment and access

Keep one API process and one workspace. Additional workers are supported:

```sh
docker compose up -d --scale worker=3
```

The web port binds to loopback. Place an HTTPS reverse proxy in front of it for remote access, and configure forwarded scheme/host handling so browser sessions receive Secure cookies. Keep the API, database, evidence store, and gateway private.

Use the bootstrap owner to create individual members under **Settings → Access**. Viewers read; analysts scan and triage; owners manage scope, schedules, settings, and membership. Member keys are shown once, stored as hashes, expire within 1–90 days, and can be revoked. Initial keys expire after seven days. Disabling a member invalidates their keys. Use member keys for automation rather than sharing the bootstrap token.

Browser cookies contain random session IDs, with credentials retained only in the web process. Sessions expire after eight hours or 30 minutes without an API request. Logout revokes that session and aborts its active requests and event streams; it does not revoke the member's automation key. Member key revocation and disabling still take effect at the API. The session store supports one web process, holds at most 1,000 sessions, and is cleared on web-service restart. Existing credential-based cookies require a fresh sign-in after upgrading. Multiple web replicas require a shared session store before deployment.

## Notification webhooks

Owners can register up to 32 Slack, Discord, or generic JSON webhooks. Destinations must use HTTPS on port 443, without URL user credentials or fragments. Every connection resolves and checks all returned addresses, rejects private/loopback/link-local destinations, and connects to a checked IP. Redirects and environment HTTP proxies are not used. Existing HTTP or private-network destinations remain stored but cannot deliver; replace them with public HTTPS endpoints. Webhooks are integrations separate from domain-scoped scanner traffic.

All roles, including owners, receive masked webhook URLs in snapshots, event streams, and create/list responses. Test and delete saved hooks by ID. Paths and query values remain only in server-side storage for delivery. New audit entries omit destination URLs; legacy webhook-creation audit entries are masked in responses without rewriting stored append-only history. Backups still contain webhook credentials. Rotate integration credentials that may have been exposed to viewers before upgrading.

Test delivery waits up to five seconds for the destination, outside the workspace lock. A missing saved ID returns 404 without falling back to a supplied URL. Delivery errors omit credential-bearing URLs. Report query filters and webhook deletion IDs are preserved by the web proxy.

## Health, reports, and API access

```sh
docker compose ps
docker compose logs --tail=50 worker api gateway
```

Authenticated routes include `/api/health`, `/api/state`, `/api/events` (SSE), and `/api/reports.pdf`. The route/role reference is served at `/openapi.json` and maintained in [public/openapi.json](../public/openapi.json). Complete request schemas and generated clients are still pending.

Member API keys can be supplied as `Authorization: Bearer <member-key>`. Owners can read Prometheus metrics at `/api/metrics`; metrics omit target, member, and evidence labels. PDF reports support `targetId`, `severity`, and `status` filters and omit raw evidence and notes. CSV exports follow the active view filters.

HTTP telemetry uses fixed route shapes and a shared unknown-route bucket, with bounded method/status labels. Arbitrary paths and HTTP methods cannot create additional metric series.

## Ownership verification

To require DNS verification, set `REQUIRE_DNS_VERIFICATION=true` in `.env` and recreate the API:

```sh
docker compose up -d api
```

Publish the exact value from target details at `_surfacer.<domain>`, then choose **Check verification**. With Cloudflare, the record name is `_surfacer`. A TXT record at the root does not satisfy the check. Allow recursive resolver caches to expire after publishing.

Required mode checks ownership at scan creation, worker claim, stage start, and every 15 minutes. Losing proof pauses the target and cancels active scans. Optional mode skips the ownership gate and leaves the verification status unchanged.

Checks use the gateway's DNS resolver because the API has no direct internet route. A resolver outage produces HTTP 503; missing or mismatched proof produces HTTP 422. Investigate resolver failures separately from incorrect records.

## Backups and restore

Back up both PostgreSQL and the evidence bucket. From the repository root, with the Compose stack available:

```sh
python3 scripts/backup.py /absolute/path/to/new-backup.dump
```

The helper creates a mode-0600 PostgreSQL custom archive and SHA-256 sidecar, verifies the archive index, and refuses to overwrite an existing file. Evidence is not included; back up the S3 bucket separately with your storage tooling. Keep `.env` in a separate secure recovery location.

Restore into a new isolated PostgreSQL instance:

```sh
pg_restore --no-owner --no-acl --dbname=<new-database> <backup.dump>
```

Apply migrations and role grants, restore the corresponding evidence bucket, and validate records and evidence access before switching deployments. A complete database-plus-evidence recovery drill has not yet been demonstrated by the project.

`docker compose down` retains named volumes. Do not use `down -v` unless you intend to delete stored workspace and evidence data.

## Delete records from active views

Workspace owners can delete records from Findings, Inventory, Endpoints (including historical URLs), Scan activity, Hazards, and Takeovers. Check individual rows, use **Select this page**, or choose **Select all matching** to include filtered results across pages. Selection follows the current target scope, search, and filters. Changing those filters clears selection; new live observations are not automatically selected. Review the selected count and confirm **Delete records**. Viewers and analysts cannot delete records, including through direct API calls.

Only finished scan runs can be deleted (completed, partial, failed, or canceled). Active queued/running/retrying runs are excluded from selection and rejected by the API. Targets and append-only audit records have no deletion control.

Deletion removes records from active workspace views, reports, relevant metrics, and MCP reads. It retains internal history, fingerprints, timestamps, triage decisions, scan lineage, checkpoints, and evidence references. It is not a storage or evidence purge, finding resolution, or proof of a clean assessment. Deleting an asset hides its nested endpoints from active inventory; it does not delete findings or scan history. Deleting an endpoint or scan does not cascade into findings. A fresh scan that observes a deleted record may bring it back while preserving its history; an existing run or retained recovery checkpoint does not undo deletion. Deleted finished scan history stays hidden while remaining available internally for scheduling and lifecycle continuity.

The API accepts `DELETE /api/<resource>` with `{"ids":["record-id"]}`, for resources `findings`, `assets`, `endpoints`, `scans`, `hazards`, and `takeovers`. `DELETE /api/<resource>/<id>` deletes a single record. Each request validates 1–100 unique existing IDs before mutation and commits deletion and audit entries together. Repeating an already deleted ID is safe. The UI sends larger selections as bounded batches; a failure stops further batches and reports confirmed progress. Refresh before retrying an interrupted operation because a lost response may follow a successful commit.

Deletion markers use existing JSON/JSONB storage; no schema migration or additional database privileges are needed. JSON development state and PostgreSQL backups retain these markers. Evidence retention continues to follow the existing policy.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Web port already in use | Set `FRONTEND_PORT` to an unused port |
| Scans unavailable in local development | `npm run dev` does not start scanner workers; use Compose for live scans |
| Worker not ready | Inspect worker/API/gateway logs and service health; the first image build downloads scanner releases |
| Partial scan or scanner deadline | Review stage diagnostics and saved coverage, then resume unfinished work; see [scanning](scanning.md) |
| Gateway name fails in scanner output | Rebuild the worker; scanner proxy configuration resolves the internal gateway with system DNS before using the public scanner resolver |
| HTTP 403/429/503 from a target | Respect cooldowns, inspect coverage warnings, and reduce scan load; blocked hosts retain prior findings |
| Existing finding did not resolve | Resolution requires two successful host/template checks; partial or skipped checks do not count |
| Historical endpoint is not live | Archive results are intentionally separate and unverified |

For defects, include redacted logs, service versions, the failing stage, and a minimal reproduction. Never include `.env`, session cookies, access keys, or raw secret evidence in a public issue.
