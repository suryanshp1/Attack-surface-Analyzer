"use client";

import { useState } from "react";
import { BulkDeleteToolbar, SelectionCheckbox, useRecordSelection } from "@/components/record-selection";
import {
  Flame,
  Search,
  ExternalLink,
  ShieldCheck,
} from "lucide-react";
import {
  dateTime,
  relative,
  api,
  exportCSV,
  type SubdomainTakeover,
} from "@/lib/types";

import { useWorkspaceFilter, useWorkspaceRoute, setWorkspaceQuery } from "@/lib/workspace-route";
import { hostInScope } from "@/lib/domain-scope";

export function TakeoversView({
  takeovers = [],
  mutate,
  scope = "all",
  canDelete = false,
  canTriage = false,
}: {
  takeovers?: SubdomainTakeover[];
  mutate?: (path: string, method: string, data?: unknown, message?: string) => Promise<boolean>;
  scope?: string;
  canDelete?: boolean;
  canTriage?: boolean;
}) {
  const [requestedFilter, setFilter] = useWorkspaceFilter("takeoverStatus", "all");
  const filter = ["all", "open", "suppressed", "resolved"].includes(requestedFilter) ? requestedFilter : "all";
  const { query } = useWorkspaceRoute();
  const setQuery = setWorkspaceQuery;
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const scoped = takeovers.filter((t) => {
    return hostInScope(t.subdomain, scope);
  });

  const filtered = scoped.filter((t) => {
    if (filter !== "all" && t.status !== filter) return false;
    if (!query) return true;
    const q = query.toLowerCase();
    return (
      t.subdomain.toLowerCase().includes(q) ||
      t.cname.toLowerCase().includes(q) ||
      t.serviceProvider.toLowerCase().includes(q)
    );
  });

  const selectionKey = JSON.stringify([scope, query, filter]);
  const selection = useRecordSelection(filtered.map(t => t.id), selectionKey);
  const updateStatus = async (id: string, newStatus: string) => {
    setBusyId(id);
    setError("");
    try {
      if (mutate) {
        if (!await mutate(`takeovers/${id}`, "PATCH", { status: newStatus }, `Takeover status set to ${newStatus}`)) {
          setError("Status was not changed. Review the error and try again.");
        }
      } else {
        await api(`takeovers/${id}`, "PATCH", { status: newStatus });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to update takeover status.");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-4">
      <button hidden id="export-takeovers" onClick={() => exportCSV("takeovers", [
        ["Subdomain", "Provider", "CNAME", "Status", "First seen", "Last seen"],
        ...filtered.map(t => [t.subdomain, t.serviceProvider, t.cname, t.status, t.firstSeen, t.lastSeen]),
      ])}>Export takeovers CSV</button>
      {error && <p role="alert" className="assessment-error">{error}</p>}
      <div className="tab-line" role="group" aria-label="Takeover status filter">
        {["all", "open", "suppressed", "resolved"].map((s) => {
          const count = scoped.filter((t) => s === "all" || t.status === s).length;
          return (
            <button
              key={s}
              className={filter === s ? "tab-active" : ""}
              aria-pressed={filter === s}
              onClick={() => setFilter(s)}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
              <span className="ml-1.5 opacity-75">{count}</span>
            </button>
          );
        })}
      </div>

      <div className="filter-bar">
        <div className="table-search assessment-search">
          <Search size={16} />
          <input
            type="search"
            aria-label="Search takeovers"
            placeholder="Search subdomain, CNAME, or provider…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      {canDelete && mutate && <BulkDeleteToolbar key={selectionKey} selection={selection} resource="takeovers" mutate={mutate} />}
      {filtered.length === 0 ? (
        <div className="empty-state p-12 text-center border rounded-xl">
          <ShieldCheck size={36} className="mx-auto mb-3 opacity-60 text-emerald-600" />
          <h3 className="text-base font-semibold">No Takeover Candidates</h3>
          <p className="text-sm opacity-70 mt-1 max-w-md mx-auto">
            {query || filter !== "all"
              ? "No records match the active filter or search query."
              : "No orphaned CNAME records pointing to unclaimed third-party cloud services were discovered."}
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="data-table responsive-table assessment-table">
            <thead>
              <tr>
                {canDelete && mutate && <th className="selection-cell"><SelectionCheckbox label="Select all filtered takeovers" checked={filtered.length > 0 && filtered.every(t => selection.selected.has(t.id))} mixed={selection.selected.size > 0 && selection.selected.size < filtered.length} onChange={() => selection.togglePage(filtered.map(t => t.id))} /></th>}
                <th>Subdomain</th>
                <th>Cloud Service</th>
                <th>Terminal CNAME Target</th>
                <th>Status</th>
                <th>First / Last Seen</th>
                {canTriage && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => {
                const isOpen = t.status === "open";
                const isResolved = t.status === "resolved";
                return (
                  <tr key={t.id}>
                    {canDelete && mutate && <td className="selection-cell" data-label="Select"><SelectionCheckbox label={`Select takeover: ${t.subdomain} · ${t.serviceProvider}`} checked={selection.selected.has(t.id)} onChange={() => selection.toggle(t.id)} /></td>}
                    <td data-label="Subdomain" className="mobile-full-cell">
                      <div className="assessment-host">
                        <Flame
                          size={15}
                          className={isOpen ? "text-rose-500" : "opacity-40"}
                        />
                        <span className="font-mono font-medium text-sm">{t.subdomain}</span>
                        <a
                          href={`http://${t.subdomain}`}
                          target="_blank"
                          rel="noreferrer"
                          className="icon-button assessment-external"
                          aria-label={`Open ${t.subdomain} in a new tab`}
                        >
                          <ExternalLink size={12} />
                        </a>
                      </div>
                    </td>
                    <td data-label="Provider">
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-neutral-200 dark:bg-neutral-800">
                        {t.serviceProvider}
                      </span>
                    </td>
                    <td data-label="CNAME target" className="font-mono text-xs opacity-80 break-all mobile-full-cell">{t.cname}</td>
                    <td data-label="Status">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${
                          isOpen
                            ? "bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300"
                            : isResolved
                              ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300"
                              : "bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300"
                        }`}
                      >
                        {t.status.toUpperCase()}
                        {t.reopenCount > 0 && (
                          <span className="ml-1 opacity-75">({t.reopenCount}x)</span>
                        )}
                      </span>
                    </td>
                    <td data-label="First / last seen" className="assessment-timestamps">
                      <span title={dateTime(t.firstSeen)}>First: {relative(t.firstSeen)}</span>
                      <span title={dateTime(t.lastSeen)}>Last: {relative(t.lastSeen)}</span>
                    </td>
                    {canTriage && <td data-label="Actions" className="assessment-actions">
                      {isOpen ? (
                        <button
                          disabled={busyId === t.id}
                          onClick={() => updateStatus(t.id, "suppressed")}
                          className="button button-secondary"
                        >
                          Suppress
                        </button>
                      ) : (
                        <button
                          disabled={busyId === t.id}
                          onClick={() => updateStatus(t.id, "open")}
                          className="button button-secondary"
                        >
                          Reopen
                        </button>
                      )}
                    </td>}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
