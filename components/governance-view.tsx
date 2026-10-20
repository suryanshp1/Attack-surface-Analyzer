"use client";

import { Mail, Server, KeyRound, ShieldCheck } from "lucide-react";
import { exportCSV, type DomainDNSPosture } from "@/lib/types";
import { useWorkspaceFilter } from "@/lib/workspace-route";
import { hostInScope } from "@/lib/domain-scope";

export function GovernanceView({ dnsPosture = [], scope = "all" }: {
  dnsPosture?: DomainDNSPosture[];
  scope?: string;
}) {
  const filtered = dnsPosture.filter(p => hostInScope(p.domain, scope));
  const [selectedDomain, setSelectedDomain] = useWorkspaceFilter("dnsDomain", "");
  const active = filtered.find(p => p.domain === selectedDomain) ?? filtered[0];
  const exportButton = <button hidden id="export-governance" onClick={() => exportCSV("dns-governance", [
    ["Domain", "SPF status", "SPF record", "DMARC policy", "DMARC record", "DKIM observed", "MX hosts", "Observed at"],
    ...(active ? [[active.domain, active.spfStatus, active.spfRecord, active.dmarcPolicy, active.dmarcRecord, active.dkimDetected, active.mxRecords?.map(mx => mx.host).join("; "), active.createdAt]] : []),
  ])}>Export DNS governance CSV</button>;

  if (!active) return <>
    {exportButton}
    <div className="empty-state"><Mail size={32} /><h3>No DNS governance observations</h3>
      <p>Run an authorized scan to evaluate SPF, DMARC, common DKIM selectors, and MX records for this scope.</p>
    </div>
  </>;

  const spfTone = active.spfStatus === "secure" ? "success" : active.spfStatus === "softfail" ? "warning" : "critical";
  const dmarcTone = active.dmarcPolicy === "reject" ? "success" : active.dmarcPolicy === "quarantine" ? "warning" : "critical";
  return <div className="governance-view">
    {exportButton}
    {filtered.length > 1 && <div className="tab-line" role="group" aria-label="DNS domain">
      {filtered.map(p => <button key={p.domain} className={active.domain === p.domain ? "tab-active" : ""}
        aria-pressed={active.domain === p.domain} onClick={() => setSelectedDomain(p.domain)}>{p.domain}</button>)}
    </div>}
    <p className="assessment-note">Observations for <strong>{active.domain}</strong>. Published policy does not establish how every receiving mail server handles a message.</p>
    <div className="governance-grid">
      <section className={`posture-card posture-${spfTone}`} aria-labelledby="spf-heading">
        <header><h3 id="spf-heading"><Mail size={16} /> SPF policy</h3><span className={`badge badge-${spfTone}`}>{active.spfStatus}</span></header>
        <p>{active.spfStatus === "secure"
          ? "The published SPF record ends in hard fail (-all). Receivers decide how to handle unauthorized senders."
          : active.spfStatus === "softfail"
            ? "The SPF record uses soft fail (~all). Review whether a stricter sender policy fits this domain."
            : active.spfStatus === "permissive"
              ? "The SPF record has a permissive policy (+all or ?all). Review the authorized sender configuration."
              : "No SPF record was observed in this scan."}</p>
        {active.spfRecord && <pre className="dns-record"><code>{active.spfRecord}</code></pre>}
      </section>
      <section className={`posture-card posture-${dmarcTone}`} aria-labelledby="dmarc-heading">
        <header><h3 id="dmarc-heading"><ShieldCheck size={16} /> DMARC policy</h3><span className={`badge badge-${dmarcTone}`}>{active.dmarcPolicy}</span></header>
        <p>{active.dmarcPolicy === "reject"
          ? "The domain requests rejection of messages that fail DMARC alignment (p=reject)."
          : active.dmarcPolicy === "quarantine"
            ? "The domain requests quarantine for messages that fail DMARC alignment (p=quarantine)."
            : active.dmarcPolicy === "none"
              ? "The domain requests monitoring without enforcement (p=none). Review reports before strengthening policy."
              : "No DMARC policy was observed in this scan."}</p>
        {active.dmarcRecord && <pre className="dns-record"><code>{active.dmarcRecord}</code></pre>}
      </section>
      <section className="posture-card" aria-labelledby="dkim-heading">
        <header><h3 id="dkim-heading"><KeyRound size={16} /> DKIM selectors</h3><span className={`badge ${active.dkimDetected ? "badge-success" : "badge-warning"}`}>{active.dkimDetected ? "Observed" : "Unconfirmed"}</span></header>
        <p>{active.dkimDetected
          ? "A public key record was observed on a common selector. Message signing and signature validity were not tested."
          : "No key was observed on the checked common selectors. A custom selector may still be in use."}</p>
      </section>
    </div>
    <section className="governance-mx" aria-labelledby="mx-heading">
      <div className="section-title"><h3 id="mx-heading"><Server size={17} /> Mail exchange (MX) records</h3><span className="badge">{active.mxRecords?.length ?? 0} servers</span></div>
      {!active.mxRecords?.length ? <p className="assessment-note">No MX records were observed for {active.domain}.</p> : (
        <div className="table-wrap"><table className="data-table responsive-table assessment-table mx-table">
          <thead><tr><th>Mail server</th><th>Priority</th><th>Resolved addresses</th></tr></thead>
          <tbody>{active.mxRecords.map((mx, index) => <tr key={`${mx.host}-${index}`}>
            <td data-label="Mail server" className="font-mono mobile-full-cell">{mx.host}</td>
            <td data-label="Priority">{mx.pref}</td>
            <td data-label="Resolved addresses" className="font-mono">{mx.ips?.length ? mx.ips.join(", ") : "Unresolved"}</td>
          </tr>)}</tbody>
        </table></div>
      )}
    </section>
  </div>;
}
