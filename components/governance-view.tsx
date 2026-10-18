"use client";

import { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Mail,
  Server,
  KeyRound,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { dateTime, relative, type DomainDNSPosture } from "@/lib/types";

export function GovernanceView({
  dnsPosture = [],
  scope = "all",
}: {
  dnsPosture?: DomainDNSPosture[];
  scope?: string;
}) {
  const filtered = dnsPosture.filter((p) => {
    if (scope !== "all" && p.domain !== scope && !p.domain.endsWith("." + scope)) {
      return false;
    }
    return true;
  });

  const [selectedDomain, setSelectedDomain] = useState<string>(
    filtered[0]?.domain || "",
  );

  const activePosture =
    filtered.find((p) => p.domain === selectedDomain) || filtered[0];

  if (!activePosture) {
    return (
      <div className="empty-state p-12 text-center border rounded-xl">
        <Mail size={36} className="mx-auto mb-3 opacity-60 text-neutral-500" />
        <h3 className="text-base font-semibold">No Email & DNS Governance Records</h3>
        <p className="text-sm opacity-70 mt-1 max-w-md mx-auto">
          Run a scan against a verified root domain to evaluate SPF, DMARC, DKIM, and MX configurations.
        </p>
      </div>
    );
  }

  const spfColor =
    activePosture.spfStatus === "secure"
      ? "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800"
      : activePosture.spfStatus === "softfail"
        ? "text-amber-600 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800"
        : "text-rose-600 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800";

  const dmarcColor =
    activePosture.dmarcPolicy === "reject"
      ? "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800"
      : activePosture.dmarcPolicy === "quarantine"
        ? "text-amber-600 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800"
        : "text-rose-600 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800";

  return (
    <div className="space-y-6">
      {filtered.length > 1 && (
        <div className="tab-line">
          {filtered.map((p) => (
            <button
              key={p.domain}
              className={activePosture.domain === p.domain ? "tab-active" : ""}
              onClick={() => setSelectedDomain(p.domain)}
            >
              {p.domain}
            </button>
          ))}
        </div>
      )}

      {/* Overview Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF Posture */}
        <div className={`p-4 rounded-xl border ${spfColor}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider opacity-80 flex items-center gap-1.5">
              <Mail size={14} /> SPF Authentication
            </span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full border bg-white dark:bg-neutral-900 uppercase">
              {activePosture.spfStatus}
            </span>
          </div>
          <p className="text-xs mt-2 leading-relaxed">
            {activePosture.spfStatus === "secure"
              ? "Strict hard fail (-all) policy enforced. Rejects unauthorized sender IPs."
              : activePosture.spfStatus === "softfail"
                ? "Soft fail (~all) policy configured. Prone to spoofing acceptance by some MTAs."
                : activePosture.spfStatus === "permissive"
                  ? "Permissive policy (+all / ?all). Domain has no active protection against email spoofing."
                  : "No SPF record found. Receivers cannot verify authorized outbound mail servers."}
          </p>
          {activePosture.spfRecord && (
            <div className="mt-3 p-2 bg-neutral-900 text-neutral-200 rounded font-mono text-xs break-all">
              {activePosture.spfRecord}
            </div>
          )}
        </div>

        {/* DMARC Posture */}
        <div className={`p-4 rounded-xl border ${dmarcColor}`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider opacity-80 flex items-center gap-1.5">
              <ShieldCheck size={14} /> DMARC Alignment
            </span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full border bg-white dark:bg-neutral-900 uppercase">
              {activePosture.dmarcPolicy}
            </span>
          </div>
          <p className="text-xs mt-2 leading-relaxed">
            {activePosture.dmarcPolicy === "reject"
              ? "Strict rejection (p=reject) policy. Unaligned fraudulent emails are blocked."
              : activePosture.dmarcPolicy === "quarantine"
                ? "Quarantine (p=quarantine) policy. Unaligned emails delivered to junk folders."
                : activePosture.dmarcPolicy === "none"
                  ? "Monitoring (p=none) only. Spoofed emails will still be delivered to inboxes."
                  : "No DMARC policy record published. Domain is susceptible to brand impersonation."}
          </p>
          {activePosture.dmarcRecord && (
            <div className="mt-3 p-2 bg-neutral-900 text-neutral-200 rounded font-mono text-xs break-all">
              {activePosture.dmarcRecord}
            </div>
          )}
        </div>

        {/* DKIM Posture */}
        <div className="p-4 rounded-xl border bg-neutral-50 dark:bg-neutral-900/60 border-neutral-200 dark:border-neutral-800">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider opacity-80 flex items-center gap-1.5">
              <KeyRound size={14} /> DKIM Selectors
            </span>
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${
                activePosture.dkimDetected
                  ? "text-emerald-600 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300"
                  : "text-amber-600 bg-amber-50 dark:bg-amber-950/40 border-amber-300"
              }`}
            >
              {activePosture.dkimDetected ? "DETECTED" : "UNCONFIRMED"}
            </span>
          </div>
          <p className="text-xs mt-2 leading-relaxed opacity-80">
            {activePosture.dkimDetected
              ? "Valid cryptographic signature keys detected on standard enterprise selectors (google, default, or k1)."
              : "Common selectors (google, default, k1) did not publish public key records. Custom selector may be in use."}
          </p>
          <div className="mt-3 text-xs opacity-75">
            Evaluated on: <span className="font-mono">{activePosture.domain}</span>
          </div>
        </div>
      </div>

      {/* MX Records Section */}
      <div className="border rounded-xl p-4 bg-white dark:bg-neutral-900/40">
        <div className="flex items-center gap-2 mb-3">
          <Server size={16} className="opacity-70" />
          <h3 className="text-sm font-semibold">Mail Exchange (MX) Infrastructure</h3>
          <span className="text-xs px-2 py-0.5 rounded-full bg-neutral-100 dark:bg-neutral-800 ml-auto">
            {activePosture.mxRecords?.length || 0} servers
          </span>
        </div>
        {!activePosture.mxRecords || activePosture.mxRecords.length === 0 ? (
          <p className="text-xs opacity-60">No MX records found for {activePosture.domain}.</p>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Mail Server Host</th>
                  <th>Priority (Pref)</th>
                  <th>Resolved IP Addresses</th>
                </tr>
              </thead>
              <tbody>
                {activePosture.mxRecords.map((mx, idx) => (
                  <tr key={idx}>
                    <td className="font-mono text-xs font-medium">{mx.host}</td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-xs bg-neutral-100 dark:bg-neutral-800">
                        {mx.pref}
                      </span>
                    </td>
                    <td className="font-mono text-xs opacity-80">
                      {mx.ips && mx.ips.length > 0 ? mx.ips.join(", ") : "Unresolved"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
