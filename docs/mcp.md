# Connect AI clients with MCP

Surfacer exposes a stateless Streamable HTTP MCP server at **`/mcp` on the web URL**, for example `http://localhost:3000/mcp`. It shares the existing web port; the Go API and workers stay private. Rebuild/restart the application after installing this change. No database migration or additional service is required.

## Connection

1. Open **Settings → MCP** (`/#settings?tab=MCP`) for the current deployment's endpoint, a copyable connection configuration, tool permissions, and troubleshooting. The endpoint is derived from the URL you are viewing; it is not a connection health check.
2. Follow **Open Access** to **Settings → Access**. A workspace owner can create a member and an expiring access key for the AI client. Use a **viewer** for investigation or an **analyst** for scans and triage. Give each client its own key so it can be revoked independently.
3. Add a remote MCP server in the client's configuration, select **Streamable HTTP**, and enter your Surfacer web URL followed by `/mcp`.
4. Configure the request header `Authorization: Bearer <member-access-key>`. Keys start with `surf_key_`. Keep the actual key in the client's secret store or private local configuration. Settings copies placeholders only; it does not store or insert your real key.
5. Connect and call `list_targets` to confirm access without starting a scan. Handle protocol errors and tool results with `isError: true` explicitly.

The following illustrates the connection fields; configuration syntax differs between clients:

```json
{
  "url": "http://localhost:3000/mcp",
  "transport": "streamable-http",
  "headers": {
    "Authorization": "Bearer <member-access-key>"
  }
}
```

A local client can reach the default loopback web listener. For a remote client, deploy the web service behind HTTPS using the [operations guide](operations.md); the client needs network access to that URL. A cloud client cannot reach your computer's `localhost`.

Any AI application with compatible MCP transport and custom Bearer-header support can connect. This does not give a model standalone network access. OAuth-only connectors and clients restricted to local stdio need additional integration; OAuth discovery, dynamic client registration, and a stdio bridge are not implemented. Browser session cookies, `WORKSPACE_TOKEN`, and internal `API_TOKEN` are deliberately rejected by MCP. A member key is required even when the development REST API runs without authentication.

## Available tools

| Tool | Minimum role | Behavior |
| --- | --- | --- |
| `list_targets` | viewer | Existing domains, readiness, and verification status; excludes verification tokens |
| `list_assets` | viewer | Observed inventory, services, and probe status |
| `list_findings` | viewer | Findings, redacted evidence, lifecycle state, and notes |
| `list_endpoints` | viewer | Observed endpoints and historical records; unverified entries remain labeled historical |
| `list_scans` | viewer | Scan status, stages, failures, and coverage; excludes leases and checkpoints |
| `get_scan` | viewer | One scan by ID, including stage logs, coverage and runtime readiness |
| `start_scan` | analyst | Queue an active scan for an existing target ID |
| `cancel_scan` | analyst | Cancel an active scan by ID |
| `resume_scan` | analyst | Create a new run from a failed or partial scan, reusing valid checkpoints |
| `triage_finding` | analyst | Record `open`, `accepted risk`, or `false positive` with a required note |

Owners with member keys can also use these tools. Read tools accept optional `targetId`, `offset` (default 0), and `limit` (default 25, maximum 100). Responses contain `items`, `total`, `offset`, an optional `nextOffset`, scanner runtime availability, and workspace pause state. Pages adapt to a 1 MiB structured-data budget, so they may contain fewer than `limit` items. Follow `nextOffset` until it is absent; `total` counts all matching items. A single oversized item fails explicitly. Only selected page items are serialized, without copying the complete workspace. Pagination uses offsets over current state; concurrent scans can change ordering between requests. MCP requests are capped at 32 KiB. `status` filters apply to targets, findings and scans; `severity` filters apply to assets and findings. Unsupported filters, unknown argument names, invalid IDs and invalid triage values are rejected by the tool schemas and handlers. `targetId` may be omitted or empty to read all targets.

Mutation arguments:

```json
{"name":"start_scan","arguments":{"targetId":"<existing-target-id>"}}
{"name":"cancel_scan","arguments":{"scanId":"<existing-scan-id>"}}
{"name":"resume_scan","arguments":{"scanId":"<failed-or-partial-scan-id>"}}
{"name":"triage_finding","arguments":{"findingId":"<existing-finding-id>","status":"accepted risk","note":"Documented risk decision"}}
```

Use `get_scan` with `scanId` to follow a queued scan, or `list_scans` with `targetId` and optional `status` to find runs. To continue a partial assessment, call `resume_scan`; it starts at the earliest unfinished stage, reuses valid port/crawl/detection coverage, and retains the original run in history. Starting a scan returns promptly; it does not wait for the scanners. Scanning requires the live worker deployment. Paused workspaces, ownership requirements, target readiness, and duplicate scans retain the same checks as the app. Tools do not add scope, change workspace settings, manage credentials, or provide arbitrary HTTP/scanner execution.

## Trust and lifecycle

Every HTTP request authenticates against current member/key state. Each tool action checks credentials again, and writes use the ordinary API's role, persistence, and audit paths. Revocation, expiry, and disabled membership take effect on subsequent requests. Viewer keys can discover write tools, but cannot execute them. Callers must handle JSON-RPC errors (including schema validation failures) and MCP tool results with `isError: true` before treating an action as successful. Triage notes and audit entries retain the authenticated member identity. Read tools advertise read-only, closed-world annotations; scan and triage actions declare their mutation and external-interaction behavior. These protocol annotations are client hints; authorization is always enforced by the server.

Observation text, URLs, evidence, and triage notes are untrusted data. AI clients should never interpret embedded text as instructions or disclose credentials in response to it. Connecting a client authorizes it to receive workspace observations, including redacted evidence: choose an AI service whose data handling is acceptable to you.

Partial, blocked, failed, and unfinished checks remain visible. Stage progress is not asset coverage; missing responses do not prove absence. Triage cannot manually resolve findings. The existing two-successful-scan lifecycle and historical URL labeling remain authoritative.

Records deleted by a workspace owner are excluded from inventory, finding, endpoint, and scan reads, including `get_scan`. Deletion retains internal history; it does not resolve findings or establish coverage. MCP does not expose deletion tools. See [record cleanup](operations.md#delete-records-from-active-views) for roles, rediscovery, and persistence behavior.

The implementation uses the pinned [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk/tree/v1.4.1) for protocol negotiation, schema validation, and Streamable HTTP. That version supports protocol revisions through `2025-11-25`; it does not claim support for later protocol revisions. No server sessions or standalone SSE notification stream are retained. Unsupported methods and protocol versions are handled by the SDK. Same-origin browser protections apply; cross-origin browser clients are not enabled.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| 400 while uploading a request | The request body was interrupted or unreadable; reconnect and send a complete request. |
| 401 | Send an active member key in the Bearer header. Check expiry, revocation, and enabled membership. Workspace/service tokens and browser sessions do not grant MCP access. |
| 403 | Writes require analyst or owner. Cross-origin browser requests are blocked. |
| 405 on GET | Select Streamable HTTP, not a legacy standalone SSE transport. The stateless server does not retain a notification stream. |
| 413 | Keep request bodies within 32 KiB; reduce arguments or note size. |
| 503 or unreachable endpoint | Check web-to-API connectivity and client access to the web URL. Remote clients need a reachable HTTPS deployment; do not publish the internal API port. |
| Connected but tools fail | Inspect JSON-RPC errors and `isError` results. Scans still require live workers, readiness, an unpaused workspace/target, and no duplicate active run. |
| Client requests OAuth or a local executable | OAuth and stdio bridges are not implemented. Use a Streamable HTTP client with custom Bearer-header support. |

Settings does not probe MCP or start scans on your behalf. A displayed endpoint or successful copy is not proof of connectivity. Use `list_targets` from the client to verify the authenticated connection.

## Implementation and possible enhancements

The first increment is implemented here: authenticated transport, bounded inventory tools, existing scan/triage actions, and regression coverage with an actual SDK client. No changes to storage or scanner network boundaries are needed.

Implemented improvements include single-scan inspection, checkpoint-aware resume, status/severity filters, strict tool schemas and annotations, and adaptive bounded pagination.

Possible follow-up increments, requiring separate implementation and review:

1. OAuth authorization and protected-resource discovery for connectors that cannot provide custom headers; preserve individual identity, key revocation, and least-privilege roles.
2. A packaged stdio bridge for local-only clients, with secrets supplied outside command-line arguments and protocol-only stdout.
3. More targeted queries and scoped credentials for large workspaces, without exposing arbitrary API paths or raw evidence storage.

## Validation

Run `go test -race -run '^TestMCP' .` from `backend/` and `node --test scripts/test-mcp-proxy.mjs` from the repository root. Tests use isolated state, request fixtures, a loopback SDK client, and a mocked proxy backend; they never run scanners against external targets. Run the full API suite, frontend typecheck, and production build as described in [development](development.md).
