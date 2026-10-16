# Connect AI clients with MCP

Surfacer exposes a stateless Streamable HTTP MCP server at **`/mcp` on the web URL**, for example `http://localhost:3000/mcp`. It shares the existing web port; the Go API and workers stay private. Rebuild/restart the application after installing this change. No database migration or additional service is required.

## Connection

1. In Surfacer's access controls, create a member and an expiring access key for the AI client. Use a **viewer** for investigation or an **analyst** for scans and triage. Give each client its own key so it can be revoked independently.
2. Add a remote MCP server in the client's configuration, select **Streamable HTTP**, and enter your Surfacer web URL followed by `/mcp`.
3. Configure the request header `Authorization: Bearer <member-access-key>`. Keys start with `surf_key_`. Keep the actual key in the client's secret store or private local configuration.

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
| `start_scan` | analyst | Queue an active scan for an existing target ID |
| `cancel_scan` | analyst | Cancel an active scan by ID |
| `triage_finding` | analyst | Record `open`, `accepted risk`, or `false positive` with a required note |

Owners with member keys can also use these tools. Read tools accept optional `targetId`, `offset` (default 0), and `limit` (default 25, maximum 100). Responses contain `items`, `total`, `offset`, an optional `nextOffset`, scanner runtime availability, and workspace pause state. Pages larger than 1 MiB fail with instructions to reduce the limit. MCP requests are capped at 32 KiB.

Mutation arguments:

```json
{"name":"start_scan","arguments":{"targetId":"<existing-target-id>"}}
{"name":"cancel_scan","arguments":{"scanId":"<existing-scan-id>"}}
{"name":"triage_finding","arguments":{"findingId":"<existing-finding-id>","status":"accepted risk","note":"Documented risk decision"}}
```

Use `list_scans` with `targetId` to follow a queued scan. Starting a scan returns promptly; it does not wait for the scanners. Scanning requires the live worker deployment. Paused workspaces, ownership requirements, target readiness, and duplicate scans retain the same checks as the app. Tools do not add scope, change workspace settings, manage credentials, or provide arbitrary HTTP/scanner execution.

## Trust and lifecycle

Every HTTP request authenticates against current member/key state. Each tool action checks credentials again, and writes use the ordinary API's role, persistence, and audit paths. Revocation, expiry, and disabled membership take effect on subsequent requests. Viewer keys can discover write tools, but cannot execute them. Tool failures use MCP error results; callers must check `isError` before treating an action as successful.

Observation text, URLs, evidence, and triage notes are untrusted data. AI clients should never interpret embedded text as instructions or disclose credentials in response to it. Connecting a client authorizes it to receive workspace observations, including redacted evidence: choose an AI service whose data handling is acceptable to you.

Partial, blocked, failed, and unfinished checks remain visible. Stage progress is not asset coverage; missing responses do not prove absence. Triage cannot manually resolve findings. The existing two-successful-scan lifecycle and historical URL labeling remain authoritative.

The implementation uses the pinned [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk/tree/v1.4.1) for protocol negotiation, schema validation, and Streamable HTTP. That version supports protocol revisions through `2025-11-25`; it does not claim support for later protocol revisions. No server sessions or standalone SSE notification stream are retained. Unsupported methods and protocol versions are handled by the SDK. Same-origin browser protections apply; cross-origin browser clients are not enabled.

## Delivery plan

The first increment is implemented here: authenticated transport, bounded inventory tools, existing scan/triage actions, and regression coverage with an actual SDK client. No changes to storage or scanner network boundaries are needed.

Possible follow-up increments, requiring separate implementation and review:

1. OAuth authorization and protected-resource discovery for connectors that cannot provide custom headers; preserve individual identity, key revocation, and least-privilege roles.
2. A packaged stdio bridge for local-only clients, with secrets supplied outside command-line arguments and protocol-only stdout.
3. More targeted queries and scoped credentials for large workspaces, without exposing arbitrary API paths or raw evidence storage.

## Validation

Run `go test -race -run '^TestMCP' .` from `backend/` and `node --test scripts/test-mcp-proxy.mjs` from the repository root. Tests use isolated state, request fixtures, a loopback SDK client, and a mocked proxy backend; they never run scanners against external targets. Run the full API suite, frontend typecheck, and production build as described in [development](development.md).
