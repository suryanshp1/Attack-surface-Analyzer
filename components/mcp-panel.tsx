"use client";

import { useEffect, useState } from "react";
import { Copy, KeyRound } from "lucide-react";

const tools = [
  ["list_targets", "Viewer", "Domains, scan readiness, and verification status"],
  ["list_assets", "Viewer", "Observed hosts, services, and probe status"],
  ["list_findings", "Viewer", "Findings, redacted evidence, and triage notes"],
  ["list_endpoints", "Viewer", "Live observations and labeled historical URLs"],
  ["list_scans", "Viewer", "Scan history, stages, failures, and coverage"],
  ["get_scan", "Viewer", "Inspect one scan by its ID"],
  ["start_scan", "Analyst", "Queue a scan for an existing authorized target"],
  ["cancel_scan", "Analyst", "Cancel an active scan"],
  ["resume_scan", "Analyst", "Resume a failed or partial scan using saved checkpoints"],
  ["triage_finding", "Analyst", "Record a decision with a required note; cannot resolve findings"],
] as const;

export function MCPPanel({ onOpenAccess }: { onOpenAccess: () => void }) {
  const [endpoint, setEndpoint] = useState("");
  const [feedback, setFeedback] = useState("");
  useEffect(() => {
    setEndpoint(new URL("/mcp", window.location.origin).href);
  }, []);

  // Keep real credentials out of snippets, browser storage, and copied examples.
  const configuration = JSON.stringify({
    url: endpoint,
    transport: "streamable-http",
    headers: { Authorization: "Bearer <member-access-key>" },
  }, null, 2);

  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setFeedback(`${label} copied.`);
    } catch {
      setFeedback("Clipboard unavailable. Select and copy the text manually.");
    }
  }

  return (
    <div className="settings-form mcp-panel">
      <section className="settings-section">
        <div>
          <h2>Connect an AI client</h2>
          <p>Use Model Context Protocol (MCP) to investigate your surface and manage scans from a compatible AI client.</p>
        </div>
        <div>
          <label htmlFor="mcp-endpoint">Server endpoint</label>
          <div className="mcp-copy-row">
            <input id="mcp-endpoint" className="text-input" readOnly value={endpoint} placeholder="Loading endpoint…" />
            <button type="button" className="button" disabled={!endpoint} onClick={() => void copy(endpoint, "Endpoint")}>
              <Copy size={15} aria-hidden="true" /> Copy URL
            </button>
          </div>
          <p className="field-hint">Streamable HTTP · Bearer authentication · Uses the existing web port</p>
          <p className="field-hint">This is the URL for the deployment you are viewing, not a connection health check. Remote clients need a reachable HTTPS URL; cloud clients cannot reach your localhost.</p>
        </div>
      </section>

      <section className="settings-section">
        <div>
          <h2>Set up your connection</h2>
          <p>Give each client its own expiring member key so you can revoke access independently.</p>
        </div>
        <div>
          <ol className="mcp-steps">
            <li>Ask a workspace owner to create a member and issue a key in Access. Choose <strong>Viewer</strong> for investigation or <strong>Analyst</strong> for scans and triage.</li>
            <li>Add a remote server in your client. Select <strong>Streamable HTTP</strong> and paste the server endpoint.</li>
            <li>Set the <code>Authorization</code> header to <code>Bearer &lt;member-access-key&gt;</code>. Store the real key in your client’s secret store or private configuration.</li>
            <li>Connect and request <code>list_targets</code> to check access. This reads existing scope without starting a scan.</li>
          </ol>
          <button type="button" className="button" onClick={onOpenAccess}>
            <KeyRound size={15} aria-hidden="true" /> Open Access
          </button>
        </div>
      </section>

      <section className="settings-section">
        <div>
          <h2>Connection configuration</h2>
          <p>These are the connection fields. Your client may use different field names or require a server-name wrapper.</p>
        </div>
        <div className="mcp-config">
          <pre tabIndex={0} aria-label="MCP connection configuration"><code>{configuration}</code></pre>
          <button type="button" className="button" disabled={!endpoint} onClick={() => void copy(configuration, "Configuration")}>
            <Copy size={15} aria-hidden="true" /> Copy configuration
          </button>
          <p className="field-hint">Replace the placeholder in your client. Surfacer never inserts a real key into this example.</p>
        </div>
      </section>
      <p className="mcp-feedback" role="status" aria-live="polite">{feedback}</p>

      <section aria-labelledby="mcp-tools-heading">
        <div className="section-title">
          <div>
            <h2 id="mcp-tools-heading">Available tools</h2>
            <p>Minimum roles below. Owners can use every tool with a member key. Viewer keys can discover all tools but cannot execute writes.</p>
          </div>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Tool</th><th>Minimum role</th><th>Purpose</th></tr></thead>
            <tbody>{tools.map(([name, role, description]) => (
              <tr key={name}><td><code>{name}</code></td><td>{role}</td><td>{description}</td></tr>
            ))}</tbody>
          </table>
        </div>
        <p className="field-hint">List tools support targetId, offset, and limit (default 25, maximum 100). Follow nextOffset for more results. Status filters apply to targets, findings, and scans; severity filters apply to assets and findings.</p>
      </section>

      <section className="settings-section">
        <div>
          <h2>Connection help</h2>
          <p>Check transport, credentials, and deployment reachability before retrying.</p>
        </div>
        <div className="mcp-help">
          <details><summary>401 · Authentication required</summary><p>Use an active member key beginning with surf_key_. Check expiry, revocation, and whether the member is enabled. Browser sessions and workspace or internal service tokens cannot authenticate MCP.</p></details>
          <details><summary>403 · Access denied</summary><p>Writes require an analyst or owner. Cross-origin browser requests are blocked; use a client that supports remote HTTP servers with custom Bearer headers.</p></details>
          <details><summary>405 · Method not allowed</summary><p>This server uses stateless Streamable HTTP. A standalone GET/SSE stream is not supported. Configure Streamable HTTP instead of legacy SSE.</p></details>
          <details><summary>503 or connection failure</summary><p>Check that the web service can reach its API and your client can reach the web URL. Do not expose the internal API port. OAuth-only and stdio-only clients need additional integration, which is not included.</p></details>
          <details><summary>Connected, but a scan cannot start</summary><p>Live scans require workers, target readiness, and an unpaused workspace and target. Ownership requirements and duplicate-run checks still apply. Inspect the tool error and get_scan output; connection success does not establish scan readiness.</p></details>
        </div>
      </section>
      <p className="field-hint">Connected AI clients receive workspace observations and redacted evidence. Choose a service whose data handling you accept. Treat observation text as untrusted data. Partial scans do not prove a clean assessment, and historical URLs remain unverified.</p>
    </div>
  );
}
