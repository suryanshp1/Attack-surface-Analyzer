"use client";

import { useState } from "react";
import {
  Search,
  TriangleAlert,
  ShieldAlert,
  FileCode2,
  ExternalLink,
} from "lucide-react";
import { dateTime, relative, type EndpointHazard } from "@/lib/types";

export function HazardsView({
  hazards = [],
  scope = "all",
}: {
  hazards?: EndpointHazard[];
  scope?: string;
}) {
  const [activeClass, setActiveClass] = useState<string>("all");
  const [query, setQuery] = useState("");

  const scoped = hazards.filter((h) => {
    if (scope !== "all" && !h.url.includes(scope)) return false;
    return true;
  });

  const filtered = scoped.filter((h) => {
    if (activeClass !== "all" && h.hazardClass !== activeClass) return false;
    if (!query) return true;
    const q = query.toLowerCase();
    return h.url.toLowerCase().includes(q) || h.parameter.toLowerCase().includes(q);
  });

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
      {/* Tab Filter Line */}
      <div className="tab-line" role="group" aria-label="Hazard class filter">
        {Object.keys(hazardLabels).map((key) => {
          const count = scoped.filter((h) => key === "all" || h.hazardClass === key).length;
          return (
            <button
              key={key}
              className={activeClass === key ? "tab-active" : ""}
              onClick={() => setActiveClass(key)}
            >
              {hazardLabels[key]}
              <span className="ml-1.5 opacity-75">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Search Bar */}
      <div className="filter-bar flex items-center justify-between gap-4">
        <div className="search-field relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
          <input
            type="text"
            className="w-full pl-9 pr-3 py-1.5 rounded-md border text-sm"
            placeholder="Search crawled parameter hazard URLs or parameter keys…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

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
          <table className="data-table responsive-table">
            <thead>
              <tr>
                <th>Hazard Category</th>
                <th>Parameter / File</th>
                <th>Target Endpoint URL (Sanitized)</th>
                <th>Severity</th>
                <th>Discovered</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((h) => {
                const isHigh = h.severity === "high" || h.severity === "critical";
                return (
                  <tr key={h.id}>
                    <td>
                      <span className="font-semibold text-xs px-2 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800">
                        {hazardLabels[h.hazardClass] || h.hazardClass}
                      </span>
                    </td>
                    <td>
                      <span className="font-mono text-xs font-bold text-amber-600 dark:text-amber-400">
                        {h.parameter}
                      </span>
                    </td>
                    <td>
                      <span className="font-mono text-xs opacity-85 break-all">{h.url}</span>
                    </td>
                    <td>
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
                    <td className="text-xs opacity-75">
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
