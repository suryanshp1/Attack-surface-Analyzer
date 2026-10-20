"use client";

import {
  Search,
  FileCode2,
} from "lucide-react";
import { dateTime, relative, exportCSV, type EndpointHazard } from "@/lib/types";
import { BulkDeleteToolbar, SelectionCheckbox, useRecordSelection } from "@/components/record-selection";

import { useWorkspaceFilter, useWorkspaceRoute, setWorkspaceQuery } from "@/lib/workspace-route";
import { urlInScope } from "@/lib/domain-scope";

export function HazardsView({
  hazards = [],
  scope = "all",
  canDelete = false,
  mutate,
}: {
  hazards?: EndpointHazard[];
  scope?: string;
  canDelete?: boolean;
  mutate?: (path: string, method: string, data?: unknown, message?: string) => Promise<boolean>;
}) {
  const [requestedClass, setActiveClass] = useWorkspaceFilter("hazardClass", "all");
  const activeClass = ["all", "ssrf_candidate", "redirect_candidate", "lfi_candidate", "sqli_candidate", "debug_flag", "sensitive_file"].includes(requestedClass) ? requestedClass : "all";
  const { query } = useWorkspaceRoute();
  const setQuery = setWorkspaceQuery;

  const scoped = hazards.filter((h) => {
    return urlInScope(h.url, scope);
  });

  const filtered = scoped.filter((h) => {
    if (activeClass !== "all" && h.hazardClass !== activeClass) return false;
    if (!query) return true;
    const q = query.toLowerCase();
    return h.url.toLowerCase().includes(q) || h.parameter.toLowerCase().includes(q);
  });

  const selectionKey = JSON.stringify([scope, query, activeClass]);
  const selection = useRecordSelection(filtered.map(h => h.id), selectionKey);
  const hazardLabels: Record<string, string> = {
    all: "All Hazards",
    ssrf_candidate: "SSRF Candidates",
    redirect_candidate: "Open Redirect",
    lfi_candidate: "Path Traversal / LFI",
    sqli_candidate: "SQL Injection",
    debug_flag: "Debug / Admin Flags",
    sensitive_file: "Sensitive Files",
  };

  return (
    <div className="space-y-4">
      <button hidden id="export-hazards" onClick={() => exportCSV("hazards", [
        ["Category", "Parameter / file", "URL", "Review priority", "Discovered"],
        ...filtered.map(h => [h.hazardClass, h.parameter, h.url, h.severity, h.createdAt]),
      ])}>Export hazards CSV</button>
      {/* Tab Filter Line */}
      <div className="tab-line" role="group" aria-label="Hazard class filter">
        {Object.keys(hazardLabels).map((key) => {
          const count = scoped.filter((h) => key === "all" || h.hazardClass === key).length;
          return (
            <button
              key={key}
              className={activeClass === key ? "tab-active" : ""}
              aria-pressed={activeClass === key}
              onClick={() => setActiveClass(key)}
            >
              {hazardLabels[key]}
              <span className="ml-1.5 opacity-75">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Search Bar */}
      <div className="filter-bar">
        <div className="table-search assessment-search">
          <Search size={16} />
          <input
            type="search"
            aria-label="Search hazards"
            placeholder="Search URL or parameter…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      <p className="assessment-note">Review candidates only. Parameter names and file paths do not confirm an exploitable vulnerability.</p>
      {canDelete && mutate && <BulkDeleteToolbar key={selectionKey} selection={selection} resource="hazards" mutate={mutate} />}
      {/* Table / Empty State */}
      {filtered.length === 0 ? (
        <div className="empty-state p-12 text-center border rounded-xl">
          <FileCode2 size={36} className="mx-auto mb-3 opacity-60 text-neutral-500" />
          <h3 className="text-base font-semibold">No Endpoint Parameter Hazards</h3>
          <p className="text-sm opacity-70 mt-1 max-w-md mx-auto">
            {query || activeClass !== "all"
              ? "No records match the active filter or search query."
              : "No heuristic high-risk parameter hazards or exposed debug/config endpoints detected."}
          </p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="data-table responsive-table assessment-table">
            <thead>
              <tr>
                {canDelete && mutate && <th className="selection-cell"><SelectionCheckbox label="Select all filtered hazards" checked={filtered.length > 0 && filtered.every(h => selection.selected.has(h.id))} mixed={selection.selected.size > 0 && selection.selected.size < filtered.length} onChange={() => selection.togglePage(filtered.map(h => h.id))} /></th>}
                <th>Hazard Category</th>
                <th>Parameter / File</th>
                <th>Target Endpoint URL (Sanitized)</th>
                <th>Review priority</th>
                <th>Discovered</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((h) => {
                const isHigh = h.severity === "high" || h.severity === "critical";
                return (
                  <tr key={h.id}>
                    {canDelete && mutate && <td className="selection-cell" data-label="Select"><SelectionCheckbox label={`Select hazard: ${h.hazardClass} · ${h.url} · ${h.parameter}`} checked={selection.selected.has(h.id)} onChange={() => selection.toggle(h.id)} /></td>}
                    <td data-label="Category">
                      <span className="font-semibold text-xs px-2 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800">
                        {hazardLabels[h.hazardClass] || h.hazardClass}
                      </span>
                    </td>
                    <td data-label="Parameter / file">
                      <span className="font-mono text-xs font-bold text-amber-600 dark:text-amber-400">
                        {h.parameter}
                      </span>
                    </td>
                    <td data-label="Endpoint URL" className="mobile-full-cell">
                      <span className="font-mono text-xs opacity-85 break-all">{h.url}</span>
                    </td>
                    <td data-label="Review priority">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${
                          isHigh
                            ? "bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300"
                            : "bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300"
                        }`}
                      >
                        {h.severity.toUpperCase()}
                      </span>
                    </td>
                    <td data-label="Discovered" className="text-xs opacity-75">
                      <span title={dateTime(h.createdAt)}>{relative(h.createdAt)}</span>
                    </td>
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
