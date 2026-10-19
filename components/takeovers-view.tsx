"use client";

import { useState } from "react";
import {
  Flame,
  Search,
  ExternalLink,
  ShieldCheck,
  Check,
  ShieldAlert,
} from "lucide-react";
import {
  dateTime,
  relative,
  api,
  type SubdomainTakeover,
} from "@/lib/types";

export function TakeoversView({
  takeovers = [],
  mutate,
  scope = "all",
}: {
  takeovers?: SubdomainTakeover[];
  mutate?: (path: string, method: string, data?: unknown, message?: string) => Promise<boolean>;
  scope?: string;
}) {
  const [filter, setFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const scoped = takeovers.filter((t) => {
    if (scope !== "all" && !t.subdomain.endsWith(scope)) return false;
    return true;
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

  const updateStatus = async (id: string, newStatus: string) => {
    setBusyId(id);
    try {
      if (mutate) {
        await mutate(`takeovers/${id}`, "PATCH", { status: newStatus }, `Takeover status set to ${newStatus}`);
      } else {
        await api(`takeovers/${id}`, "PATCH", { status: newStatus });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="space-y-4">
      <div className="tab-line" role="group" aria-label="Takeover status filter">
        {["all", "open", "suppressed", "resolved"].map((s) => {
          const count = scoped.filter((t) => s === "all" || t.status === s).length;
          return (
            <button
              key={s}
              className={filter === s ? "tab-active" : ""}
              onClick={() => setFilter(s)}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
              <span className="ml-1.5 opacity-75">{count}</span>
            </button>
          );
        })}
      </div>

      <div className="filter-bar flex items-center justify-between gap-4">
        <div className="search-field relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
          <input
            type="text"
            className="w-full pl-9 pr-3 py-1.5 rounded-md border text-sm"
            placeholder="Search by subdomain, CNAME, or cloud provider…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

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
          <table className="data-table responsive-table">
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>Cloud Service</th>
                <th>Terminal CNAME Target</th>
                <th>Status</th>
                <th>First / Last Seen</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => {
                const isOpen = t.status === "open";
                const isResolved = t.status === "resolved";
                return (
                  <tr key={t.id}>
                    <td>
                      <div className="flex items-center gap-2">
                        <Flame
                          size={15}
                          className={isOpen ? "text-rose-500" : "opacity-40"}
                        />
                        <span className="font-mono font-medium text-sm">{t.subdomain}</span>
                        <a
                          href={`http://${t.subdomain}`}
                          target="_blank"
                          rel="noreferrer"
                          className="opacity-50 hover:opacity-100"
                        >
                          <ExternalLink size={12} />
                        </a>
                      </div>
                    </td>
                    <td>
                      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-neutral-200 dark:bg-neutral-800">
                        {t.serviceProvider}
                      </span>
                    </td>
                    <td className="font-mono text-xs opacity-80 break-all">{t.cname}</td>
                    <td>
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
                    <td className="text-xs opacity-75">
                      <span title={dateTime(t.lastSeen)}>{relative(t.lastSeen)}</span>
                    </td>
                    <td className="text-right">
                      {isOpen ? (
                        <button
                          disabled={busyId === t.id}
                          onClick={() => updateStatus(t.id, "suppressed")}
                          className="text-xs px-2.5 py-1 rounded border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
                        >
                          Suppress
                        </button>
                      ) : (
                        <button
                          disabled={busyId === t.id}
                          onClick={() => updateStatus(t.id, "open")}
                          className="text-xs px-2.5 py-1 rounded border hover:bg-neutral-100 dark:hover:bg-neutral-800 transition"
                        >
                          Reopen
                        </button>
                      )}
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
