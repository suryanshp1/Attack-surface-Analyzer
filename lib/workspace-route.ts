"use client";

import { useSyncExternalStore } from "react";

export type Page =
  | "Overview"
  | "Inventory"
  | "Endpoints"
  | "Findings"
  | "Takeovers"
  | "Governance"
  | "Hazards"
  | "Changes"
  | "Scan activity"
  | "Targets"
  | "Settings";
type Detail = {
  kind: "asset" | "finding" | "target" | "scan";
  id: string;
} | null;
type Route = {
  page: Page;
  scope: string;
  query: string;
  detail: Detail;
  filters: Record<string, string>;
};
const pages: Record<string, Page> = {
  overview: "Overview",
  inventory: "Inventory",
  endpoints: "Endpoints",
  findings: "Findings",
  takeovers: "Takeovers",
  governance: "Governance",
  hazards: "Hazards",
  changes: "Changes",
  scans: "Scan activity",
  targets: "Targets",
  settings: "Settings",
};
const routeEvent = "surfacer:navigation";

export function parseWorkspaceRoute(hash: string): Route {
  const [path, search = ""] = hash.replace(/^#/, "").split("?");
  const params = new URLSearchParams(search);
  const raw = params.get("detail")?.split(":");
  const detail =
    raw && ["asset", "finding", "target", "scan"].includes(raw[0]) && raw[1]
      ? ({ kind: raw[0], id: raw[1] } as NonNullable<Detail>)
      : null;
  const filters: Record<string, string> = {};
  params.forEach((value, key) => {
    if (!["target", "q", "detail"].includes(key)) filters[key] = value;
  });
  const page = pages[path] ?? "Overview";
  let query = params.get("q") || "";
  const clauses: string[] = [];
  const migrate = (key: string, field: string) => {
    const value = filters[key];
    if (value && value !== "all")
      clauses.push(`${field}=${JSON.stringify(value)}`);
    delete filters[key];
  };
  if (page === "Inventory") {
    migrate("tech", "tech");
    migrate("port", "port");
    migrate("exposure", "exposure");
  } else if (page === "Endpoints") migrate("kind", "kind");
  else if (page === "Findings") {
    migrate("findingStatus", "status");
    migrate("severity", "severity");
    if (filters.findingCategory === "security") {
      clauses.push("security:true");
      delete filters.findingCategory;
    } else migrate("findingCategory", "category");
  } else if (page === "Hazards") migrate("hazardClass", "class");
  else if (page === "Takeovers") migrate("takeoverStatus", "status");
  else if (page === "Scan activity") migrate("scanStatus", "status");
  else if (page === "Changes") {
    if (filters.changeKind === "finding") {
      clauses.push("(kind:finding OR kind:resolved)");
      delete filters.changeKind;
    } else migrate("changeKind", "kind");
  }
  if (clauses.length)
    query = [query ? `(${query})` : "", ...clauses]
      .filter(Boolean)
      .join(" AND ");
  return {
    page,
    scope: params.get("target") || "all",
    query,
    detail,
    filters,
  };
}
function subscribe(listener: () => void) {
  window.addEventListener("popstate", listener);
  window.addEventListener("hashchange", listener);
  window.addEventListener(routeEvent, listener);
  return () => {
    window.removeEventListener("popstate", listener);
    window.removeEventListener("hashchange", listener);
    window.removeEventListener(routeEvent, listener);
  };
}
export function useWorkspaceRoute() {
  return parseWorkspaceRoute(
    useSyncExternalStore(
      subscribe,
      () => window.location.hash,
      () => "",
    ),
  );
}
export function workspaceHref(route: Route) {
  const params = new URLSearchParams(route.filters);
  if (route.scope !== "all") params.set("target", route.scope);
  if (route.query) params.set("q", route.query);
  if (route.detail)
    params.set("detail", `${route.detail.kind}:${route.detail.id}`);
  const slug =
    Object.entries(pages).find(([, value]) => value === route.page)?.[0] ??
    "overview";
  return `#${slug}${params.size ? `?${params}` : ""}`;
}
export function updateWorkspaceRoute(patch: Partial<Route>, replace = false) {
  const old = parseWorkspaceRoute(window.location.hash);
  const next = { ...old, ...patch };
  const hash = workspaceHref(next);
  if (hash === window.location.hash) return;
  const scroll = window.scrollY;
  window.history.replaceState(
    { ...window.history.state, surfacerScroll: scroll },
    "",
  );
  const entry = {
    ...window.history.state,
    surfacerScroll: next.page === old.page ? scroll : 0,
    surfacerDetail: next.detail ? window.location.hash : null,
  };
  window.history[replace ? "replaceState" : "pushState"](entry, "", hash);
  window.dispatchEvent(new Event(routeEvent));
  if (next.page !== old.page) window.scrollTo(0, 0);
}
export function openWorkspaceDetail(
  kind: NonNullable<Detail>["kind"],
  id: string,
) {
  updateWorkspaceRoute({ detail: { kind, id } });
}
export function closeWorkspaceDetail() {
  if (window.history.state?.surfacerDetail) window.history.back();
  else updateWorkspaceRoute({ detail: null }, true);
}
export function useWorkspaceFilter(
  key: string,
  fallback: string,
): [string, (value: string) => void] {
  const route = useWorkspaceRoute();
  return [
    route.filters[key] ?? fallback,
    (value) => {
      const current = parseWorkspaceRoute(window.location.hash);
      updateWorkspaceRoute({
        filters: {
          ...current.filters,
          [key]: value,
          ...(key !== "p" ? { p: "1" } : {}),
        },
      });
    },
  ];
}
export function setWorkspaceQuery(query: string) {
  const route = parseWorkspaceRoute(window.location.hash);
  updateWorkspaceRoute({ query, filters: { ...route.filters, p: "1" } });
}
