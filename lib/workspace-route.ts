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
  return {
    page: pages[path] ?? "Overview",
    scope: params.get("target") || "all",
    query: params.get("q") || "",
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
  updateWorkspaceRoute({ query, filters: { ...route.filters, p: "1" } }, true);
}
