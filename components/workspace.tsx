"use client";

import {
  Fragment,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type MouseEvent,
} from "react";
import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Compass,
  Clock3,
  Code2,
  Copy,
  Download,
  ExternalLink,
  FileText,
  Flame,
  Globe2,
  LayoutDashboard,
  Loader2,
  LockKeyhole,
  Mail,
  Menu,
  MoreHorizontal,
  Network,
  Plus,
  Radar,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Square,
  Target as TargetIcon,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  createWorkspaceSync,
  type ConnectionState,
} from "@/lib/workspace-sync";
import { QueryFilter } from "@/components/query-filter";
import { compileQuery } from "@/lib/query-language";
import { queryFields, assetDocument, findingDocument, endpointDocument, eventDocument, scanDocument } from "@/lib/query-fields";
import { eventMatchesDomain, isSecurityFinding as isSecurityIssue } from "@/lib/overview-metrics";
import { hostInScope } from "@/lib/domain-scope";
import { OverviewDashboard } from "@/components/overview-dashboard";
import { WorkspaceTour } from "@/components/workspace-tour";
import { AppearanceControl } from "@/components/appearance";
import {
  api,
  dateTime,
  exportCSV,
  relative,
  type State,
  type Asset,
  type Finding,
  type Target,
  type Scan,
  type Settings,
} from "@/lib/types";

import {
  useWorkspaceRoute,
  workspaceHref,
  useWorkspaceFilter,
  updateWorkspaceRoute,
  openWorkspaceDetail,
  closeWorkspaceDetail,
  setWorkspaceQuery,
  type Page,
} from "@/lib/workspace-route";
import type { Endpoint } from "@/lib/types";
import { TakeoversView } from "@/components/takeovers-view";
import { GovernanceView } from "@/components/governance-view";
import { HazardsView } from "@/components/hazards-view";
import { WebhooksPanel } from "@/components/webhooks-panel";
import { MCPPanel } from "@/components/mcp-panel";
import { BulkDeleteToolbar, SelectionCheckbox, useRecordSelection } from "@/components/record-selection";

const navigation = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Inventory", icon: Network },
  { name: "Endpoints", icon: Code2 },
  { name: "Findings", icon: Shield },
  { name: "Takeovers", icon: Flame },
  { name: "Governance", icon: Mail },
  { name: "Hazards", icon: TriangleAlert },
  { name: "Changes", icon: Activity },
  { name: "Scan activity", icon: Radar },
] as const;
const exportControls: Partial<Record<Page, string>> = {
  Inventory: "export-inventory",
  Endpoints: "export-endpoints",
  Changes: "export-changes",
  Hazards: "export-hazards",
  Takeovers: "export-takeovers",
  Governance: "export-governance",
  Findings: "export-findings",
};
const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
  info: 5,
};
const activeScanStatus = (status: string) =>
  ["running", "queued", "retrying"].includes(status);
const finishedScanStatus = (status: string) =>
  ["completed", "partial", "failed", "canceled"].includes(status);
function stageStatus(scan: Scan, status: string) {
  if (activeScanStatus(scan.status)) return status;
  return status === "running"
    ? "interrupted"
    : status === "pending"
      ? "not_run"
      : status;
}
const statusLabel = (status: string) =>
  status === "not_run"
    ? "Not run"
    : status.charAt(0).toUpperCase() + status.slice(1);
function scanSummary(scan: Scan) {
  const pendingStages = scan.stages.filter(
    (s) => s.status !== "completed",
  ).length;
  const pendingDetection =
    scan.stages.find((s) => s.name === "Detection")?.status !== "completed";
  if (scan.status === "completed")
    return "Bounded scan profile finished. Review findings and service coverage.";
  if (activeScanStatus(scan.status))
    return "Assessment in progress. Findings and coverage may change.";
  if (scan.status === "canceled")
    return "Scan canceled. Collected observations are retained.";
  if (scan.error) return scan.error;
  if (pendingStages === 0)
    return "All scan stages completed. Unresponsive hosts were skipped for HTTP checks; existing findings are retained.";
  return `Assessment incomplete. ${pendingDetection ? "Detection did not finish. " : "Some checks did not complete. "}Existing findings are retained.`;
}
function probeLabel(asset: Asset) {
  return (
    asset.probeStatus ||
    (asset.blocked
      ? "Probe unavailable"
      : asset.status
        ? `HTTP ${asset.status}`
        : asset.ports.some((p) =>
              [
                80, 443, 3000, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9443,
              ].includes(p),
            )
          ? "No HTTP response"
          : "Not probed")
  );
}
function CopyValue({ value, label }: { value: string; label: string }) {
  const [message, setMessage] = useState("");
  return (
    <button
      type="button"
      className="copy-value"
      aria-label={`Copy ${label}`}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setMessage("Copied");
        } catch {
          setMessage("Copy unavailable");
        }
        setTimeout(() => setMessage(""), 2500);
      }}
    >
      <Copy size={14} />
      <span>{message || `Copy ${label}`}</span>
    </button>
  );
}
function Pagination({
  total,
  page,
  setPage,
}: {
  total: number;
  page: number;
  setPage: (value: string) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / 25));
  const changePage = (value: number) => {
    setPage(String(value));
    requestAnimationFrame(() =>
      document
        .querySelector(".responsive-table, .scan-history")
        ?.scrollIntoView({ block: "start" }),
    );
  };
  if (!total) return null;
  return (
    <nav className="pagination" aria-label="Result pages">
      <span>
        {(page - 1) * 25 + 1}–{Math.min(page * 25, total)} of {total}
      </span>
      <button
        className="button button-secondary"
        disabled={page <= 1}
        onClick={() => changePage(page - 1)}
      >
        <ChevronLeft size={16} />
        Previous
      </button>
      <span>
        Page {page} of {pages}
      </span>
      <button
        className="button button-secondary"
        disabled={page >= pages}
        onClick={() => changePage(page + 1)}
      >
        Next
        <ChevronRight size={16} />
      </button>
    </nav>
  );
}
function useResultPage(total: number) {
  const [value, setPage] = useWorkspaceFilter("p", "1");
  const page = Math.min(
    Math.max(1, Math.floor(Number(value) || 1)),
    Math.max(1, Math.ceil(total / 25)),
  );
  return { page, setPage, start: (page - 1) * 25 };
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand">
      <div className="brand-symbol">
        <span />
        <span />
        <span />
      </div>
      {!compact && (
        <span>
          surfacer<span className="brand-period">.</span>
        </span>
      )}
    </div>
  );
}
function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}
function Severity({ value }: { value: string }) {
  return (
    <span className={`severity severity-${value}`}>
      <i />
      {value === "none"
        ? "No findings"
        : value.charAt(0).toUpperCase() + value.slice(1)}
    </span>
  );
}
function Button({
  children,
  onClick,
  primary = false,
  disabled = false,
  className = "",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  primary?: boolean;
  disabled?: boolean;
  className?: string;
  type?: "button" | "submit";
}) {
  return (
    <button
      type={type}
      className={`button ${primary ? "button-primary" : "button-secondary"} ${className}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}
function Empty({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Radar size={30} />
      </div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}
function Modal({
  title,
  children,
  onClose,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const old = document.activeElement as HTMLElement;
    const el = ref.current;
    el?.focus();
    document.body.style.overflow = "hidden";
    function keys(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && el) {
        const items = Array.from(
          el.querySelectorAll<HTMLElement>(
            "button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],summary",
          ),
        ).filter((item) => item.getClientRects().length > 0);
        const first = items[0],
          last = items[items.length - 1];
        if (
          e.shiftKey &&
          (document.activeElement === first || document.activeElement === el)
        ) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    }
    document.addEventListener("keydown", keys);
    return () => {
      document.removeEventListener("keydown", keys);
      document.body.style.overflow = "";
      old?.focus();
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className={`modal ${wide ? "modal-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={ref}
        tabIndex={-1}
      >
        <div className="modal-heading">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export default function Workspace() {
  const [state, setState] = useState<State | null>(null),
    [error, setError] = useState(""),
    [toast, setToast] = useState(""),
    [toastError, setToastError] = useState(false),
    [mobile, setMobile] = useState(false),
    [modal, setModal] = useState<"target" | "scan" | "help" | null>(null),
    [notice, setNotice] = useState(false),
    [tourOpen, setTourOpen] = useState(false),
    [auth, setAuth] = useState(false),
    [connection, setConnection] = useState<ConnectionState>("connecting"),
    [lastUpdate, setLastUpdate] = useState("");
  const sync = useRef<ReturnType<typeof createWorkspaceSync<State>> | null>(
    null,
  );
  const route = useWorkspaceRoute();
  const { page, scope, query } = route;
  const setQuery = setWorkspaceQuery;
  const setScope = (value: string) =>
    updateWorkspaceRoute({
      scope: value,
      detail: null,
      filters: { ...route.filters, p: "1" },
    });
  const asset =
    state?.assets.find(
      (a) => route.detail?.kind === "asset" && a.id === route.detail.id,
    ) ?? null;
  const target =
    state?.targets.find(
      (a) => route.detail?.kind === "target" && a.id === route.detail.id,
    ) ?? null;
  const scan =
    state?.scans.find(
      (a) => route.detail?.kind === "scan" && a.id === route.detail.id,
    ) ?? null;
  const findingID = route.detail?.kind === "finding" ? route.detail.id : null;
  const setAsset = (value: Asset | null) =>
    value ? openWorkspaceDetail("asset", value.id) : closeWorkspaceDetail();
  const setTarget = (value: Target | null) =>
    value ? openWorkspaceDetail("target", value.id) : closeWorkspaceDetail();
  const setScan = (value: Scan | null) =>
    value ? openWorkspaceDetail("scan", value.id) : closeWorkspaceDetail();
  const setFindingID = (value: string | null) =>
    value ? openWorkspaceDetail("finding", value) : closeWorkspaceDetail();
  const drawerRef = useRef<HTMLElement>(null);
  const menuRef = useRef<HTMLButtonElement>(null);
  const refresh = useCallback(async () => {
    await sync.current?.refresh();
  }, []);
  useEffect(() => {
    const updates = createWorkspaceSync<State>({
      snapshot(value) {
        setState(value);
        setAuth(false);
        setLastUpdate(new Date().toISOString());
      },
      connection: setConnection,
      error: setError,
      unauthorized() {
        setAuth(true);
      },
      fetchState: (signal) =>
        fetch("/api/state", { signal, cache: "no-store" }),
      openStream: () => new EventSource("/api/events"),
      visible: () => document.visibilityState !== "hidden",
    });
    sync.current = updates;
    const visibility = () => updates.visibilityChanged();
    document.addEventListener("visibilitychange", visibility);
    void updates.refresh();
    return () => {
      updates.stop();
      sync.current = null;
      document.removeEventListener("visibilitychange", visibility);
    };
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 4500);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    const keys = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        document.getElementById("global-search")?.click();
      }
    };
    window.addEventListener("keydown", keys);
    return () => window.removeEventListener("keydown", keys);
  }, []);
  const navigationHref = (next: Page) =>
    workspaceHref({
      ...route,
      page: next,
      query: "",
      detail: null,
      filters: { ...route.filters, p: "1" },
    });
  const followNavigation = (
    event: MouseEvent<HTMLAnchorElement>,
    next: Page,
  ) => {
    if (
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      event.button !== 0
    )
      return;
    event.preventDefault();
    go(next);
  };
  const go = (next: Page) => {
    updateWorkspaceRoute({
      page: next,
      query: "",
      detail: null,
      filters: { ...route.filters, p: "1" },
    });
    setMobile(false);
    setNotice(false);
  };
  useEffect(() => {
    const restore = () =>
      requestAnimationFrame(() =>
        window.scrollTo(0, window.history.state?.surfacerScroll ?? 0),
      );
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);
  useEffect(() => {
    if (!mobile) return;
    const drawer = drawerRef.current;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawer?.querySelector<HTMLElement>("button,a[href]")?.focus();
    const keys = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobile(false);
      if (e.key === "Tab" && drawer) {
        const items = [
          ...drawer.querySelectorAll<HTMLElement>(
            "a[href],button,select,input",
          ),
        ].filter((el) => el.getBoundingClientRect().height > 0);
        const first = items[0],
          last = items[items.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", keys);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", keys);
      menuRef.current?.focus();
    };
  }, [mobile]);
  useEffect(() => {
    const media = window.matchMedia("(min-width: 761px)");
    const close = () => {
      if (media.matches) setMobile(false);
    };
    media.addEventListener("change", close);
    return () => media.removeEventListener("change", close);
  }, []);
  const mutate = async (
    path: string,
    method: string,
    data?: unknown,
    message = "Changes saved",
  ) => {
    try {
      if (path.includes("/cancel") && method === "POST") {
        const match = path.match(/scans\/([^/]+)\/cancel/);
        if (match) {
          const scanId = match[1];
          setState((prev) => {
            if (!prev) return prev;
            return {
              ...prev,
              scans: prev.scans.map((s) =>
                s.id === scanId
                  ? {
                      ...s,
                      status: "canceled",
                      stages: s.stages.map((st) =>
                        st.status === "running" || st.status === "pending"
                          ? { ...st, status: "canceled" }
                          : st,
                      ),
                    }
                  : s,
              ),
            };
          });
        }
      }
      await api(path, method, data);
      await refresh();
      setToastError(false);
      setToast(message);
      return true;
    } catch (e) {
      setToastError(true);
      setToast((e as Error).message);
      await refresh();
      return false;
    }
  };
  const startTour = () => {
    setModal(null);
    setMobile(false);
    setNotice(false);
    setTourOpen(true);
  };
  const closeTour = useCallback(() => setTourOpen(false), []);
  const closeModal = useCallback(() => setModal(null), []),
    closeFinding = useCallback(closeWorkspaceDetail, []),
    closeAsset = useCallback(closeWorkspaceDetail, []),
    closeTarget = useCallback(closeWorkspaceDetail, []),
    closeScan = useCallback(closeWorkspaceDetail, []);
  if (auth) return <Auth onSuccess={refresh} />;
  if (!state)
    return (
      <div className="loading-screen">
        <Brand />
        <div>
          {error ? (
            <>
              <TriangleAlert />
              <h2>Workspace unavailable.</h2>
              <p>{error}</p>
              <Button onClick={() => void refresh()}>Try again</Button>
            </>
          ) : (
            <>
              <Loader2 className="spin" />
              <p>Getting your surface in sight…</p>
            </>
          )}
        </div>
      </div>
    );
  const canManage = state.me?.role === "owner";
  const canTriage = canManage || state.me?.role === "analyst";
  const memberName = state.me?.name || "Workspace member";
  const memberRole = state.me?.role || "viewer";
  const initials = memberName.split(/\s+/).map(part => part[0]).slice(0, 2).join("").toUpperCase();
  const scopedAssets = state.assets.filter(
    (a) => scope === "all" || a.targetId === scope,
  );
  const scopeDomain = state.targets.find(target => target.id === scope)?.domain;
  const scopedFindings = state.findings.filter(finding =>
    scope === "all" || (!!scopeDomain && hostInScope(finding.host, scopeDomain)),
  );
  const scopedEvents = state.events.filter(event =>
    scope === "all" || (!!scopeDomain && eventMatchesDomain(event, scopeDomain)),
  );
  const liveFinding = state.findings.find((f) => f.id === findingID);
  const liveTarget = state.targets.find((t) => t.id === target?.id);
  const liveScan = state.scans.find((s) => s.id === scan?.id);
  return (
    <div className="app-shell" data-ui>
      <a
        href="#main-content"
        className="skip-link"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main-content")?.focus();
        }}
      >
        Skip to main content
      </a>
      {mobile && (
        <div className="sidebar-scrim" onClick={() => setMobile(false)} />
      )}
      <aside
        ref={drawerRef}
        id="workspace-navigation"
        aria-label="Workspace navigation"
        className={`sidebar ${mobile ? "sidebar-open" : ""}`}
      >
        <button
          className="icon-button drawer-close"
          aria-label="Close navigation"
          onClick={() => setMobile(false)}
        >
          <X size={20} />
        </button>
        <a
          href={navigationHref("Overview")}
          className="brand-link"
          onClick={(e) => followNavigation(e, "Overview")}
          aria-label="Surfacer overview"
        >
          <Brand />
        </a>
        <button className="workspace-switch" onClick={() => go("Settings")}>
          <span className="workspace-monogram">
            {state.settings.name.slice(0, 1)}
          </span>
          <span>
            {state.settings.name}
            <small>Security workspace</small>
          </span>
          <ChevronDown size={15} />
        </button>
        <div className="nav-caption">Workspace</div>
        <nav aria-label="Main navigation">
          {navigation.map(({ name, icon: Icon }) => (
            <a
              href={navigationHref(name)}
              key={name}
              aria-current={page === name ? "page" : undefined}
              className={`nav-item ${page === name ? "nav-active" : ""}`}
              onClick={(e) => followNavigation(e, name)}
            >
              <Icon size={19} strokeWidth={1.7} />
              <span>{name}</span>
              {name === "Findings" && (
                <span className="nav-count">
                  {scopedFindings.filter((f) => f.status === "open").length}
                </span>
              )}
              {name === "Changes" && <span className="new-dot" />}
            </a>
          ))}
        </nav>
        <div className="nav-caption manage-caption">Manage</div>
        <nav aria-label="Manage workspace">
          <a
            href={navigationHref("Targets")}
            aria-current={page === "Targets" ? "page" : undefined}
            className={`nav-item ${page === "Targets" ? "nav-active" : ""}`}
            onClick={(e) => followNavigation(e, "Targets")}
          >
            <TargetIcon size={19} strokeWidth={1.7} />
            Targets<span className="muted-count">{state.targets.length}</span>
          </a>
          <a
            href={navigationHref("Settings")}
            aria-current={page === "Settings" ? "page" : undefined}
            className={`nav-item ${page === "Settings" ? "nav-active" : ""}`}
            onClick={(e) => followNavigation(e, "Settings")}
          >
            <Settings2 size={19} strokeWidth={1.7} />
            Settings
          </a>
        </nav>
        <div className="sidebar-bottom">
          <div className="scope-note">
            <ShieldCheck size={19} />
            <p>
              Domain scope.
              <br />
              <span>Safe by construction.</span>
            </p>
            <button
              aria-label="Learn about domain scope"
              onClick={() => setModal("help")}
            >
              <ArrowUpRight size={16} />
            </button>
          </div>
          <button className="nav-item" onClick={() => setModal("help")}>
            <CircleHelp size={19} strokeWidth={1.7} />
            Help & documentation
            <ArrowUpRight size={14} />
          </button>
          <button className="profile" onClick={() => go("Settings")}>
            <span className="avatar">{initials}</span>
            <span>
              {memberName}
              <small>{memberRole.charAt(0).toUpperCase() + memberRole.slice(1)} · Local workspace</small>
            </span>
            <MoreHorizontal size={18} />
          </button>
        </div>
      </aside>
      <div className="main-shell" inert={mobile || undefined}>
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-label="Open navigation"
              ref={menuRef}
              aria-expanded={mobile}
              aria-controls="workspace-navigation"
              onClick={() => setMobile(true)}
            >
              <Menu size={22} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{page}</strong>
          </div>
          <div className="topbar-right">
            <button id="workspace-tour-launcher" className="icon-button" aria-label="Take a guided tour" title="Take a guided tour" onClick={startTour}>
              <Compass size={19} />
            </button>
            <AppearanceControl compact />
            <button className="global-search query-shortcut" id="global-search" onClick={() => {
              const editor = document.querySelector<HTMLElement>('[data-query-focus]');
              if (editor) editor.focus();
              else { go("Inventory"); requestAnimationFrame(() => document.querySelector<HTMLElement>('[data-query-focus]')?.focus()); }
            }}><Search size={16} /><span>Query your surface</span><kbd>⌘ K</kbd></button>

            <button
              className={`icon-button notification-button ${notice ? "notification-active" : ""}`}
              aria-label="Notifications"
              onClick={() => setNotice(!notice)}
            >
              <Bell size={19} />
              {state.events.length > 0 && <i />}
            </button>
            <button
              className="avatar avatar-small"
              aria-label="Account settings"
              onClick={() => go("Settings")}
            >
              {initials}
            </button>
          </div>
          {notice && (
            <div className="notifications">
              <h3>Latest changes</h3>
              {state.events.slice(0, 3).map((e) => (
                <button key={e.id} onClick={() => go("Changes")}>
                  <strong>{e.title}</strong>
                  <span>{e.detail}</span>
                  <small>{relative(e.at)}</small>
                </button>
              ))}
              {!state.events.length && <p>You’re all caught up.</p>}
              <Button onClick={() => go("Changes")}>
                View change feed <ArrowRight size={15} />
              </Button>
            </div>
          )}
        </header>
        <main id="main-content" tabIndex={-1} className="main-content">
          <div className="workspace-scope">
            <label htmlFor="workspace-scope">Target scope</label>
            <select
              id="workspace-scope"
              value={scope}
              onChange={(e) => setScope(e.target.value)}
            >
              <option value="all">All targets</option>
              {state.targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.domain}
                </option>
              ))}
            </select>
            {scope !== "all" && (
              <button className="text-action" onClick={() => setScope("all")}>
                View all targets <X size={14} />
              </button>
            )}
            <span>
              {["Settings", "Targets"].includes(page)
                ? "Workspace management shows all targets"
                : "Applies to this view and its exports"}
            </span>
          </div>
          <ConnectionStatus
            connection={connection}
            lastUpdate={lastUpdate}
            refresh={refresh}
          />
          <WorkspaceTour open={tourOpen} onStart={startTour} onClose={closeTour} />
          <div className="page-heading">
            <div>
              <h1>
                {page === "Overview"
                  ? "Your surface, in sight."
                  : page === "Inventory"
                    ? "Asset inventory."
                    : page === "Endpoints"
                      ? "Your application surface."
                      : page === "Findings"
                        ? "Focus on what matters."
                        : page === "Takeovers"
                          ? "Subdomain takeovers."
                          : page === "Governance"
                            ? "DNS & email hygiene."
                            : page === "Hazards"
                              ? "Endpoint parameter hazards."
                              : page === "Changes"
                                ? "Know what changed."
                                : page === "Scan activity"
                                  ? "Scan activity."
                                  : page === "Targets"
                                    ? "Your target scope."
                                    : "Workspace settings."}
              </h1>
              <p>
                {page === "Overview"
                  ? "A clear picture of your external footprint. Nothing left in the dark."
                  : page === "Inventory"
                    ? "Every discovered asset. One place to keep track."
                    : page === "Endpoints"
                      ? "Pages, APIs, forms and JavaScript discovered by Katana."
                      : page === "Findings"
                        ? "Prioritize exposures, review the evidence, and track the fix."
                        : page === "Takeovers"
                          ? "Dangling CNAMEs pointing to orphaned cloud resources with known takeover signatures."
                          : page === "Governance"
                            ? "Domain authentication hygiene, SPF policy, DMARC alignment, DKIM selectors, and MX configurations."
                            : page === "Hazards"
                              ? "Heuristic threat triage on crawled URLs and parameters without active exploitation."
                              : page === "Changes"
                                ? "The latest additions, exposures, and improvements across your surface."
                                : page === "Scan activity"
                                  ? "Follow every stage. Stay in control of every scan."
                                  : page === "Targets"
                                    ? "Choose a domain. Keep its public services in view."
                                    : "A safe, predictable workspace that works the way you do."}
              </p>
            </div>
            <div className="page-actions">
              {page === "Overview" || page === "Scan activity" ? (
                <>
                  <Button
                    onClick={() => {
                      exportCSV("report", [
                        ["Host", "Type", "IP", "Technologies", "Open findings"],
                        ...scopedAssets.map((a) => [
                          a.host,
                          a.type,
                          a.ip,
                          a.technologies.join(", "),
                          state.findings.filter(
                            (f) => f.host === a.host && f.status === "open",
                          ).length,
                        ]),
                      ]);
                      setToastError(false);
                      setToast("Inventory report exported");
                    }}
                  >
                    <Download size={16} />
                    Export report
                  </Button>
                  <Button
                    onClick={() => {
                      const params = new URLSearchParams();
                      if (scope !== "all") params.set("targetId", scope);
                      window.location.assign(`/api/reports.pdf?${params}`);
                    }}
                  >
                    <FileText size={15} />
                    PDF report
                  </Button>
                  <Button
                    primary
                    disabled={state.settings.paused || !canTriage}
                    onClick={() => setModal("scan")}
                  >
                    <Plus size={17} />
                    Run a scan
                  </Button>
                </>
              ) : page === "Targets" ? (
                <Button primary disabled={!canManage} onClick={() => setModal("target")}>
                  <Plus size={17} />
                  Add target
                </Button>
              ) : page === "Settings" ? null : (
                <Button
                  onClick={() => {
                    const exportID = exportControls[page];
                    const control = exportID ? document.getElementById(exportID) : null;
                    if (!control) {
                      setToastError(true);
                      setToast("Export is unavailable for this view. Refresh and try again.");
                      return;
                    }
                    control.click();
                    setToastError(false);
                    setToast("CSV exported");
                  }}
                >
                  <Download size={16} />
                  Export CSV
                </Button>
              )}
            </div>
          </div>
          {state.settings.paused && (
            <div className="alert-strip">
              <Square size={16} />
              Workspace scanning is paused.
              <button onClick={() => go("Settings")}>
                Manage settings <ArrowRight size={14} />
              </button>
            </div>
          )}
          {page === "Overview" && (
            <OverviewDashboard
              state={state}
              events={scopedEvents}
              scope={scope}
              go={go}
              selectFinding={setFindingID}
              run={() => setModal("scan")}
            />
          )}
          {page === "Inventory" && (
            <Inventory
              mutate={mutate}
              state={state}
              assets={scopedAssets}
              query={query}
              setQuery={setQuery}
              scope={scope}
              select={setAsset}
              add={() => setModal("target")}
            />
          )}
          {page === "Endpoints" && (
            <EndpointsPage
              canDelete={state.me?.role === "owner"}
              mutate={mutate}
              history={(state.history ?? []).filter(
                (e) => scope === "all" || e.targetId === scope,
              )}
              assets={scopedAssets}
              query={query}
              setQuery={setQuery}
              run={() => setModal("scan")}
              selectAsset={setAsset}
            />
          )}
          {page === "Findings" && (
            <Findings
              key={scope}
              canDelete={state.me?.role === "owner"}
              mutate={mutate}
              findings={scopedFindings}
              query={query}
              select={setFindingID}
              clearScope={() =>
                updateWorkspaceRoute({
                  scope: "all",
                  query: "",
                  filters: { p: "1" },
                })
              }
              scopeName={state.targets.find((t) => t.id === scope)?.domain}
            />
          )}
          {page === "Takeovers" && (
            <TakeoversView
              key={scope}
              canDelete={state.me?.role === "owner"}
              canTriage={canTriage}
              takeovers={state.takeovers || []}
              scope={state.targets.find((t) => t.id === scope)?.domain || "all"}
              mutate={mutate}
            />
          )}
          {page === "Governance" && (
            <GovernanceView
              dnsPosture={state.dnsPosture || []}
              scope={state.targets.find((t) => t.id === scope)?.domain || "all"}
            />
          )}
          {page === "Hazards" && (
            <HazardsView
              key={scope}
              canDelete={state.me?.role === "owner"}
              mutate={mutate}
              hazards={state.hazards || []}
              scope={state.targets.find((t) => t.id === scope)?.domain || "all"}
            />
          )}
          {page === "Changes" && <Changes events={scopedEvents} />}
          {page === "Targets" && (
            <Targets
              verificationRequired={
                state.runtime?.verificationRequired !== false
              }
              targets={state.targets}
              select={setTarget}
              add={() => setModal("target")}
              mutate={mutate}
            />
          )}
          {page === "Scan activity" && (
            <Scans
              canDelete={state.me?.role === "owner"}
              mutate={mutate}
              scans={state.scans.filter(
                (s) => scope === "all" || s.targetId === scope,
              )}
              select={setScan}
              run={() => setModal("scan")}
            />
          )}
          {page === "Settings" && (
            <SettingsPage
              access={state}
              settings={state.settings}
              audit={state.audit}
              mutate={mutate}
            />
          )}
          <footer className="workspace-footer">
            <span>
              <span className="status-dot" />{" "}
              {`${state.runtime?.workers ?? 0} workers online · selected domain scope`}
            </span>
            <span>
              Made to bring clarity.
              <span className="footer-brand">surfacer.</span>
            </span>
          </footer>
        </main>
      </div>
      {toast && (
        <div role={toastError ? "alert" : "status"} className={`toast ${toastError ? "toast-error" : ""}`}>
          {toastError ? <TriangleAlert size={18} /> : <Check size={18} />}
          <span>{toast}</span>
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={16} />
          </button>
        </div>
      )}
      {modal === "target" && (
        <AddTarget
          verificationRequired={state.runtime?.verificationRequired !== false}
          onClose={closeModal}
          onAdded={async (t) => {
            await refresh();
            setModal(null);
            setTarget(t);
            setToastError(false);
            setToast(
              state.runtime?.verificationRequired
                ? "Target added. Verify ownership to get started."
                : "Target added. Ready to scan.",
            );
          }}
        />
      )}
      {modal === "scan" && (
        <RunScan
          verificationRequired={state.runtime?.verificationRequired !== false}
          targets={state.targets}
          state={state}
          onClose={closeModal}
          onRun={async (id) => {
            if (
              await mutate(
                "scans",
                "POST",
                { targetId: id },
                "Scan queued. Follow its progress in Scan activity.",
              )
            ) {
              setModal(null);
              go("Scan activity");
            }
          }}
        />
      )}
      {modal === "help" && (
        <Modal title="Safe by construction." onClose={closeModal}>
          <div className="help-content">
            <ShieldCheck size={42} />
            <p>
              Surfacer discovers and monitors external assets within each
              selected domain. DNS verification follows your workspace policy.
            </p>
            <Button onClick={startTour}>
              <Compass size={16} /> Take a guided tour
            </Button>
            <h3>Start with your domain</h3>
            <p>
              Add a root domain, then start a scan. DNS verification is optional
              in this workspace unless required by the deployment policy.
            </p>
            <h3>Know what’s running</h3>
            <p>
              The Docker worker runs pinned Subfinder, DNSx, HTTPx, Katana,
              Gitleaks and Nuclei releases through a scope-checking gateway.
              Scans stay within their selected domain scope.
            </p>
            <h3>Your evidence stays yours</h3>
            <p>
              Evidence is shown as inert text. Secrets are redacted, and no data
              is sent to third parties. Review the local README for deployment
              and scope details.
            </p>
            <Button
              primary
              onClick={() => {
                setModal(null);
                go("Targets");
              }}
            >
              Manage targets <ArrowRight size={16} />
            </Button>
          </div>
        </Modal>
      )}
      {asset && (
        <AssetDetail
          asset={asset}
          findings={state.findings.filter((f) => f.host === asset.host)}
          onClose={closeAsset}
          selectFinding={(id) => {
            setFindingID(id);
          }}
        />
      )}
      {liveFinding && (
        <FindingDetail
          finding={liveFinding}
          associatedAsset={state.assets.find(
            (a) => a.host === liveFinding.host,
          )}
          onClose={closeFinding}
          mutate={mutate}
        />
      )}
      {liveTarget && (
        <TargetDetail
          verificationRequired={state.runtime?.verificationRequired !== false}
          target={liveTarget}
          onClose={closeTarget}
          mutate={mutate}
          notify={setToast}
        />
      )}
      {liveScan && (
        <ScanDetail
          scan={liveScan}
          onClose={closeScan}
          mutate={mutate}
          canManage={state.me?.role !== "viewer"}
        />
      )}
    </div>
  );
}

function EndpointsPage({
  canDelete,
  mutate,
  assets,
  history,
  query,
  setQuery,
  run,
  selectAsset,
}: {
  canDelete: boolean;
  mutate: Mutation;
  history: NonNullable<State["history"]>;
  assets: Asset[];
  query: string;
  setQuery: (s: string) => void;
  run: () => void;
  selectAsset: (a: Asset) => void;
}) {
  const [mode, setMode] = useWorkspaceFilter("mode", "live");
  const historical = mode === "historical";
  const live = assets.flatMap((a) =>
    (a.endpoints ?? [])
      .filter((e) => !e.removed)
      .map((e) => ({ ...e, host: a.host })),
  );
  const all = historical
    ? history.map((e) => ({ ...e, host: new URL(e.url).hostname }))
    : live;
  const compiled = compileQuery(query, queryFields.endpoints);
  const rows = all.filter(e => compiled.matches(endpointDocument(e)));
  const { page, setPage, start } = useResultPage(rows.length);
  const filtered = !!query;
  const route = useWorkspaceRoute();
  const selection = useRecordSelection(rows.map(e => e.id), JSON.stringify([route.scope, query, mode]));
  const visibleIDs = rows.slice(start, start + 25).map(e => e.id);
  const selectedOnPage = visibleIDs.filter(id => selection.selected.has(id)).length;
  return (
    <>
      <div className="tab-line" role="group" aria-label="Endpoint source">
        <button
          aria-pressed={!historical}
          className={!historical ? "tab-active" : ""}
          onClick={() => {
            setMode("live");
          }}
        >
          Live observations <span>{live.length}</span>
        </button>
        <button
          aria-pressed={historical}
          className={historical ? "tab-active" : ""}
          onClick={() => {
            setMode("historical");
          }}
        >
          Historical · unverified <span>{history.length}</span>
        </button>
      </div>
      <p className="view-description">
        {historical
          ? "Archived URLs from Wayback and Common Crawl. These are not proof of a currently reachable endpoint."
          : "URLs observed during bounded crawls. An error response or a discovered URL does not confirm a healthy service."}
      </p>
      <QueryFilter view="endpoints" count={rows.length} />
      {canDelete && <BulkDeleteToolbar key={JSON.stringify([route.scope, query, mode])} selection={selection} resource="endpoints" mutate={mutate} pageIDs={visibleIDs} />}
      {!rows.length ? (
        <Empty
          title={
            filtered
              ? "No endpoints match these filters."
              : historical
                ? "No historical URLs recorded."
                : "No endpoints observed in this scope."
          }
          description={
            filtered
              ? "Clear the query to see collected endpoints."
              : historical
                ? "Archived URLs appear after historical discovery completes."
                : "Review scan coverage or start a crawl to collect endpoint observations."
          }
          action={
            <Button
              onClick={
                filtered
                  ? () => {
                      setQuery("");
                    }
                  : run
              }
            >
              {filtered ? "Clear filters" : "Run a scan"}
            </Button>
          }
        />
      ) : (
        <div className="table-wrap">
          <table className="data-table responsive-table endpoint-table">
            <thead>
              <tr>
                {canDelete && <th className="selection-cell"><SelectionCheckbox label="Select all endpoints on this page" checked={visibleIDs.length > 0 && selectedOnPage === visibleIDs.length} mixed={selectedOnPage > 0 && selectedOnPage < visibleIDs.length} onChange={() => selection.togglePage(visibleIDs)} /></th>}
                <th>Endpoint</th>
                <th>Method / type</th>
                <th>Observation</th>
                <th>Parameters</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(start, start + 25).map((e) => {
                const a = assets.find((a) => a.host === e.host);
                return (
                  <tr key={e.host + e.id}>
                    {canDelete && <td className="selection-cell" data-label="Select"><SelectionCheckbox label={`Select endpoint: ${e.method} ${e.url}`} checked={selection.selected.has(e.id)} onChange={() => selection.toggle(e.id)} /></td>}
                    <td data-label="Endpoint">
                      <strong className="endpoint-url">{e.url}</strong>
                      <small className="endpoint-source">{e.source}</small>
                      <div className="inline-actions">
                        <CopyValue value={e.url} label="URL" />
                        {a && (
                          <button
                            className="text-action"
                            onClick={() => selectAsset(a)}
                          >
                            View asset
                            <ArrowRight size={14} />
                          </button>
                        )}
                      </div>
                    </td>
                    <td data-label="Method / type">
                      <Badge>{e.method}</Badge>
                      <span className="cell-secondary">{e.kind}</span>
                    </td>
                    <td data-label="Observation">
                      {historical
                        ? "Historical · unverified"
                        : e.status
                          ? `HTTP ${e.status}`
                          : "Discovered · no response"}
                    </td>
                    <td data-label="Parameter names">
                      {e.parameters.join(", ") || "None observed"}
                    </td>
                    <td data-label="Last seen">{relative(e.lastSeen)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Pagination total={rows.length} page={page} setPage={setPage} />
      <div className="table-footer">
        <span>Depth 3 · query values omitted · forms are never submitted</span>
        <button
          className="button button-secondary"
          id="export-endpoints"
          onClick={() =>
            exportCSV("endpoints", [
              [
                "URL",
                "Host",
                "Method",
                "Type",
                "Status",
                "Parameters",
                "Source",
                "First seen",
                "Last seen",
              ],
              ...rows.map((e) => [
                e.url,
                e.host,
                e.method,
                e.kind,
                e.status,
                e.parameters.join("; "),
                e.source,
                e.firstSeen,
                e.lastSeen,
              ]),
            ])
          }
        >
          <Download size={15} />
          Export {rows.length} filtered URLs
        </button>
      </div>
    </>
  );
}

function ScopeSelect({
  state,
  scope,
  setScope,
}: {
  state: State;
  scope: string;
  setScope: (s: string) => void;
}) {
  return (
    <select
      className="filter-select"
      aria-label="Target filter"
      value={scope}
      onChange={(e) => setScope(e.target.value)}
    >
      <option value="all">All targets</option>
      {state.targets.map((t) => (
        <option key={t.id} value={t.id}>
          {t.domain}
        </option>
      ))}
    </select>
  );
}
function Inventory({
  mutate,
  state,
  assets,
  query,
  setQuery,
  scope,
  select,
  add,
}: {
  mutate: Mutation;
  state: State;
  assets: Asset[];
  query: string;
  setQuery: (s: string) => void;
  scope: string;
  select: (a: Asset) => void;
  add: () => void;
}) {
  const [sort, setSort] = useWorkspaceFilter("inventorySort", "host");
  const compiled = compileQuery(query, queryFields.inventory);
  const openByHost = new Map<string, number>();
  for (const finding of state.findings) {
    if (finding.status === "open") openByHost.set(finding.host, (openByHost.get(finding.host) ?? 0) + 1);
  }
  const rows = assets.filter(a => compiled.matches(assetDocument(a, openByHost.get(a.host) ?? 0)))
    .sort((a, b) =>
      sort === "risk"
        ? severityOrder[a.severity] - severityOrder[b.severity]
        : a.host.localeCompare(b.host),
    );
  const { page, setPage, start } = useResultPage(rows.length);
  const selectionKey = JSON.stringify([scope, query]);
  const selection = useRecordSelection(rows.map(a => a.id), selectionKey);
  const visibleIDs = rows.slice(start, start + 25).map(a => a.id);
  const selectedOnPage = visibleIDs.filter(id => selection.selected.has(id)).length;
  const canDelete = state.me?.role === "owner";
  return (
    <>
      <div className="tab-line">
        <span className="tab-active">
          All assets <span>{assets.length}</span>
        </span>
        <span className="inventory-note">
          <ShieldCheck size={15} />
          Selected domain scope
        </span>
      </div>
      <QueryFilter view="inventory" count={rows.length} />
      <div className="filter-bar">
        <span>{rows.length} {rows.length === 1 ? "asset" : "assets"}</span>
        <select className="filter-select" aria-label="Sort assets" value={sort} onChange={e => setSort(e.target.value)}>
          <option value="host">Hostname A–Z</option><option value="risk">Highest severity first</option>
        </select>
      </div>
      {canDelete && <BulkDeleteToolbar key={selectionKey} selection={selection} resource="assets" mutate={mutate} pageIDs={visibleIDs} />}
      <div className="table-wrap">
        <table className="data-table responsive-table inventory-table">
          <thead>
            <tr>
              {canDelete && <th className="selection-cell"><SelectionCheckbox label="Select all assets on this page" checked={visibleIDs.length > 0 && selectedOnPage === visibleIDs.length} mixed={selectedOnPage > 0 && selectedOnPage < visibleIDs.length} onChange={() => selection.togglePage(visibleIDs)} /></th>}
              <th>Asset</th>
              <th>Technology</th>
              <th>Ports</th>
              <th>Response</th>
              <th>Open findings</th>
              <th>Last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.slice(start, start + 25).map((a) => {
              const open = state.findings.filter(
                (f) => f.host === a.host && f.status === "open",
              );
              return (
                <tr key={a.id} onClick={() => select(a)}>
                  {canDelete && <td className="selection-cell" data-label="Select"><SelectionCheckbox label={`Select asset: ${a.host}`} checked={selection.selected.has(a.id)} onChange={() => selection.toggle(a.id)} /></td>}
                  <td data-label="Asset">
                    <button
                      className="asset-cell"
                      onClick={(e) => {
                        e.stopPropagation();
                        select(a);
                      }}
                    >
                      <span className="asset-icon">
                        <Globe2 size={19} />
                      </span>
                      <span>
                        <strong>{a.host}</strong>
                        <small>{a.ip}</small>
                      </span>
                    </button>
                  </td>
                  <td data-label="Technology">
                    <div className="tech-chips">
                      {a.technologies.slice(0, 2).map((t) => (
                        <span key={t}>{t}</span>
                      ))}
                      {a.technologies.length > 2 && (
                        <span className="muted">
                          +{a.technologies.length - 2} more
                        </span>
                      )}
                      {!a.technologies.length && (
                        <span className="muted">Not identified</span>
                      )}
                    </div>
                  </td>
                  <td data-label="Open ports">
                    {a.ports.slice(0, 3).join(", ") || "None observed"}
                    {a.ports.length > 3 && (
                      <span className="cell-secondary">
                        +{a.ports.length - 3} more
                      </span>
                    )}
                  </td>
                  <td data-label="HTTP observation">
                    <span className="http-status">
                      <i />
                      {probeLabel(a)}
                    </span>
                  </td>
                  <td data-label="Open findings">
                    {open.length ? (
                      <span className="finding-count">
                        <Severity
                          value={
                            open.sort(
                              (a, b) =>
                                severityOrder[a.severity] -
                                severityOrder[b.severity],
                            )[0].severity
                          }
                        />
                        <strong>{open.length}</strong>
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td data-label="Last seen" className="muted">
                    {relative(a.lastSeen)}
                  </td>
                  <td>
                    <ChevronRight size={16} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!rows.length && (
          <Empty
            title={
              assets.length
                ? "No matching assets."
                : "Your inventory starts here."
            }
            description={
              assets.length
                ? "Try another search or clear your filters."
                : "Add a root domain to start discovery."
            }
            action={
              <Button
                onClick={
                  assets.length
                    ? () => {
                        setQuery("");
                      }
                    : add
                }
              >
                {assets.length ? "Clear filters" : "Add target"}
              </Button>
            }
          />
        )}
      </div>
      <button
        id="export-inventory"
        className="sr-only"
        onClick={() =>
          exportCSV("inventory", [
            ["Host", "Type", "IP", "Technologies", "Ports"],
            ...rows.map((a) => [
              a.host,
              a.type,
              a.ip,
              a.technologies.join(", "),
              a.ports.join(", "),
            ]),
          ])
        }
      >
        Export filtered inventory
      </button>
      <Pagination total={rows.length} page={page} setPage={setPage} />
      <div className="table-footer">
        <span>
          {rows.length} of {assets.length} assets
        </span>
        <span>
          Click an asset to explore its details <ArrowUpRight size={14} />
        </span>
      </div>
    </>
  );
}

function Findings({
  canDelete,
  mutate,
  findings,
  query,
  select,
  clearScope,
  scopeName,
}: {
  canDelete: boolean;
  mutate: Mutation;
  findings: Finding[];
  query: string;
  select: (id: string) => void;
  clearScope: () => void;
  scopeName?: string;
}) {
  const [sort, setSort] = useWorkspaceFilter("findingSort", "priority"),
    [group, setGroup] = useWorkspaceFilter("findingGroup", "none");

  const compiled = compileQuery(query, queryFields.findings);
  const rows = findings.filter(f => compiled.matches(findingDocument(f, isSecurityIssue(f))))
    .sort((a, b) => {
      if (group === "template" && a.template !== b.template)
        return a.template.localeCompare(b.template);
      if (sort === "newest") return b.firstSeen.localeCompare(a.firstSeen);
      if (sort === "oldest") return a.firstSeen.localeCompare(b.firstSeen);
      const urgency = (f: Finding) =>
        Date.parse(
          f.evidence.match(/Certificate expires: ([^\n]+)/)?.[1] || "",
        ) || Infinity;
      return (
        severityOrder[a.severity] - severityOrder[b.severity] ||
        urgency(a) - urgency(b) ||
        b.lastSeen.localeCompare(a.lastSeen)
      );
    });
  const { page, setPage, start } = useResultPage(rows.length);
  const visible = rows.slice(start, start + 25);
  const route = useWorkspaceRoute();
  const selection = useRecordSelection(rows.map(f => f.id), JSON.stringify([route.scope, query]));
  const visibleIDs = visible.map(f => f.id);
  const selectedOnPage = visibleIDs.filter(id => selection.selected.has(id)).length;
  return (
    <>
      <p className="findings-context">
        {
          findings.filter((f) => f.status === "open" && isSecurityIssue(f))
            .length
        }{" "}
        open security issues ·{" "}
        {
          findings.filter((f) => f.status === "open" && !isSecurityIssue(f))
            .length
        }{" "}
        inventory observations. Parameter hazards are candidates, not confirmed
        vulnerabilities.
      </p>
      <QueryFilter view="findings" count={rows.length} />
      <div className="filter-bar">
        <select
          className="filter-select"
          aria-label="Sort findings"
          value={sort}
          onChange={(e) => setSort(e.target.value)}
        >
          <option value="priority">Priority and certificate urgency</option>
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
        </select>
        <select
          className="filter-select"
          aria-label="Group findings"
          value={group}
          onChange={(e) => setGroup(e.target.value)}
        >
          <option value="none">No grouping</option>
          <option value="template">Group by issue type</option>
        </select>
        <button
          id="export-findings"
          className="sr-only"
          onClick={() =>
            exportCSV("findings", [
              [
                "Title",
                "Category",
                "Severity",
                "Host",
                "IP",
                "Port",
                "Matched At",
                "Status",
                "First seen",
              ],
              ...rows.map((f) => [
                f.title,
                f.category || "vulnerability",
                f.severity,
                f.host,
                f.ip || "",
                f.port || "",
                f.matchedAt || "",
                f.status,
                f.firstSeen,
              ]),
            ])
          }
        >
          Export filtered findings
        </button>
      </div>
      {canDelete ? <BulkDeleteToolbar selection={selection} resource="findings" mutate={mutate} pageIDs={visibleIDs} /> : <p className="field-hint">Only workspace owners can delete records.</p>}
      <div className="table-wrap">
        <table className="data-table responsive-table findings-table">
          <thead>
            <tr>
              {canDelete && <th className="selection-cell"><SelectionCheckbox label="Select all findings on this page" checked={visible.length > 0 && selectedOnPage === visible.length} mixed={selectedOnPage > 0 && selectedOnPage < visible.length} onChange={() => selection.togglePage(visibleIDs)} /></th>}
              <th>Finding & Discovery</th>
              <th>Severity</th>
              <th>Target Asset</th>
              <th>Port / Route</th>
              <th>First seen</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {visible.map((f, index) => (
              <Fragment key={f.id}>
                {group === "template" &&
                  (index === 0 ||
                    visible[index - 1].template !== f.template) && (
                    <tr className="group-row">
                      <th colSpan={canDelete ? 8 : 7}>
                        {f.template} ·{" "}
                        {
                          rows.filter((row) => row.template === f.template)
                            .length
                        }{" "}
                        in this view
                      </th>
                    </tr>
                  )}
                <tr onClick={() => select(f.id)}>
                  {canDelete && <td className="selection-cell" data-label="Select"><SelectionCheckbox label={`Select finding: ${f.title} · ${f.host}`} checked={selection.selected.has(f.id)} onChange={() => selection.toggle(f.id)} /></td>}
                  <td data-label="Finding">
                    <button
                      className="finding-title-cell"
                      onClick={(e) => {
                        e.stopPropagation();
                        select(f.id);
                      }}
                    >
                      <span
                        className={`finding-icon finding-icon-${f.category || f.severity || "info"}`}
                      >
                        {f.category === "port" ? (
                          <Network size={18} />
                        ) : f.category === "endpoint" ? (
                          <Globe2 size={18} />
                        ) : f.category === "hazard" ? (
                          <TriangleAlert size={18} />
                        ) : f.category === "secret" ? (
                          <LockKeyhole size={18} />
                        ) : f.category === "host" ? (
                          <TargetIcon size={18} />
                        ) : (
                          <Shield size={18} />
                        )}
                      </span>
                      <span>
                        <span className="finding-title-row">
                          <strong>{f.title}</strong>
                          {f.category && f.category !== "vulnerability" && (
                            <span className="category-tag-pill">
                              {f.category.toUpperCase()}
                            </span>
                          )}
                        </span>
                        <small>{f.matchedAt || f.host}</small>
                      </span>
                    </button>
                  </td>
                  <td data-label="Severity">
                    <Severity value={f.severity} />
                  </td>
                  <td data-label="Target Asset">
                    <span className="asset-cell-wrap">
                      <strong>{f.host}</strong>
                      {f.ip && <small className="ip-chip">{f.ip}</small>}
                    </span>
                  </td>
                  <td data-label="Port / Route">
                    {f.port ? (
                      <span className="port-badge">
                        {f.port}/{f.protocol || "tcp"}
                      </span>
                    ) : f.method ? (
                      <span className="method-badge">{f.method}</span>
                    ) : (
                      <span className="muted">{f.stageName || "—"}</span>
                    )}
                  </td>
                  <td data-label="First seen" className="muted">
                    {relative(f.firstSeen)}
                  </td>
                  <td data-label="Status">
                    <Badge
                      tone={f.status === "resolved" ? "success" : "neutral"}
                    >
                      {f.status}
                    </Badge>
                  </td>
                  <td>
                    <ChevronRight size={16} />
                  </td>
                </tr>
              </Fragment>
            ))}
          </tbody>
        </table>
        {!rows.length && (
          <Empty
            title={
              scopeName
                ? `No matching findings for ${scopeName}.`
                : "No matching findings."
            }
            description="Clear filters to review collected findings, or change the target scope above."
            action={
              <Button
                onClick={() => {
                  updateWorkspaceRoute({
                    query: "",
                    filters: { p: "1" },
                  });
                  if (!findings.length && scopeName) clearScope();
                }}
              >
                {!findings.length && scopeName
                  ? "View all targets"
                  : "Clear filters"}
              </Button>
            }
          />
        )}
      </div>
      <Pagination total={rows.length} page={page} setPage={setPage} />
      <div className="table-footer">
        <span>{rows.length} findings</span>
        <span>
          Evidence stays behind a click <LockKeyhole size={14} />
        </span>
      </div>
    </>
  );
}

function Changes({ events }: { events: State["events"] }) {
  const { query } = useWorkspaceRoute();
  const compiled = compileQuery(query, queryFields.changes);
  const rows = events.filter(e => compiled.matches(eventDocument(e)));
  return (
    <>
      <QueryFilter view="changes" count={rows.length} />
      <button
        id="export-changes"
        className="sr-only"
        onClick={() =>
          exportCSV("changes", [
            ["Event", "Detail", "Time"],
            ...rows.map((e) => [e.title, e.detail, e.at]),
          ])
        }
      >
        Export filtered changes
      </button>
      <div className="change-feed">
        {rows.map((e, i) => (
          <div className="change-item" key={e.id}>
            {(i === 0 ||
              new Date(e.at).toDateString() !==
                new Date(rows[i - 1].at).toDateString()) && (
              <h3 className="change-date">
                {new Date(e.at).toLocaleDateString(undefined, {
                  weekday: "long",
                  month: "long",
                  day: "numeric",
                })}
              </h3>
            )}
            <div className="change-card">
              <span className={`change-icon change-icon-${e.kind}`}>
                {e.kind === "resolved" ? (
                  <CheckCheck size={22} />
                ) : e.kind === "asset" ? (
                  <Globe2 size={22} />
                ) : e.kind === "port" ? (
                  <Network size={22} />
                ) : e.kind === "certificate" ? (
                  <LockKeyhole size={22} />
                ) : (
                  <Shield size={22} />
                )}
              </span>
              <div>
                <div className="change-title">
                  <h3>{e.title}</h3>
                  <Badge tone={e.kind === "resolved" ? "success" : "neutral"}>
                    {e.kind === "resolved"
                      ? "Improved"
                      : e.kind === "finding"
                        ? "Exposure"
                        : "Surface"}
                  </Badge>
                </div>
                <p>{e.detail}</p>
                {e.change && (
                  <dl className="detail-grid" aria-label="Observation changes">
                    <div><dt>Before</dt><dd>{e.change.before.join(", ")}</dd></div>
                    <div><dt>After</dt><dd>{e.change.after.join(", ")}</dd></div>
                    <div><dt>Service / host</dt><dd>{e.change.origin || e.change.host}</dd></div>
                    <div><dt>Compared scans</dt><dd><code>{e.change.previousScanId}</code> → <code>{e.change.scanId}</code></dd></div>
                  </dl>
                )}
                <span className="change-meta">
                  {e.actor} · {dateTime(e.at)}
                </span>
              </div>
              <span className="change-time">{relative(e.at)}</span>
            </div>
          </div>
        ))}
      </div>
      {!rows.length && (
        <Empty
          title="A quiet perimeter."
          description="New assets, exposures and resolved findings will appear here after successful scans."
        />
      )}
    </>
  );
}

function Targets({
  verificationRequired,
  targets,
  select,
  add,
  mutate,
}: {
  verificationRequired: boolean;
  targets: Target[];
  select: (t: Target) => void;
  add: () => void;
  mutate: Mutation;
}) {
  return (
    <>
      <div className="scope-info">
        <ShieldCheck size={24} />
        <div>
          <strong>
            {verificationRequired
              ? "Verify your domain."
              : "DNS verification is optional."}
          </strong>
          <p>
            {verificationRequired
              ? "Verify a root domain to scan its public subdomains."
              : "Add a root domain and scan its public subdomains immediately. You can verify DNS ownership at any time."}
          </p>
        </div>
      </div>
      <div className="target-grid">
        {targets.map((t) => (
          <article className="target-card" key={t.id}>
            <div className="target-top">
              <span className="target-symbol">
                <Globe2 size={28} strokeWidth={1.3} />
              </span>
              <Badge tone={t.status === "verified" ? "success" : "neutral"}>
                {t.status === "verified" ? (
                  <Check size={12} />
                ) : (
                  <Clock3 size={12} />
                )}{" "}
                {t.status === "pending" && !verificationRequired
                  ? "Unverified · ready to scan"
                  : t.status}
              </Badge>
            </div>
            <h2>{t.domain}</h2>
            <p>
              Root domain ·{" "}
              {verificationRequired
                ? "DNS verification required"
                : "DNS verification optional"}
            </p>
            <div className="target-metrics">
              <span>
                Discovered assets<strong>{t.assets}</strong>
              </span>
              <span>
                Last scan<strong>{relative(t.lastScan)}</strong>
              </span>
            </div>
            <div className="target-bottom">
              <select
                aria-label={`Schedule for ${t.domain}`}
                className="filter-select"
                value={t.schedule}
                onChange={(e) =>
                  void mutate(
                    `targets/${t.id}`,
                    "PATCH",
                    { schedule: e.target.value },
                    "Schedule updated",
                  )
                }
              >
                <option>Manual</option>
                <option>Daily</option>
                <option>Weekly</option>
              </select>
              <Button
                primary={verificationRequired && t.status !== "verified"}
                onClick={() => select(t)}
              >
                {!verificationRequired || t.status === "verified"
                  ? "View details"
                  : "Verify ownership"}
                <ArrowUpRight size={15} />
              </Button>
            </div>
          </article>
        ))}
        <button className="add-target-card" onClick={add}>
          <span>
            <Plus size={24} />
          </span>
          <strong>Add a root domain</strong>
          <p>Bring more of your surface into view.</p>
        </button>
      </div>
    </>
  );
}

function useVisibleClock(enabled: boolean) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    const update = () => {
      if (document.visibilityState !== "hidden") tick((value) => value + 1);
    };
    const timer = setInterval(update, 15000);
    document.addEventListener("visibilitychange", update);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", update);
    };
  }, [enabled]);
}
function ConnectionStatus({
  connection,
  lastUpdate,
  refresh,
}: {
  connection: ConnectionState;
  lastUpdate: string;
  refresh: () => Promise<void>;
}) {
  useVisibleClock(true);
  return (
    <div className={`connection-status connection-${connection}`} role="status">
      <span className="connection-dot" />
      {connection === "live"
        ? "Live updates connected"
        : connection === "offline"
          ? "Updates unavailable · showing saved observations"
          : "Reconnecting live updates · periodic refresh active"}
      {lastUpdate && <span>Last received {relative(lastUpdate)}</span>}
      {connection !== "live" && (
        <button className="text-action" onClick={() => void refresh()}>
          Refresh now
        </button>
      )}
    </div>
  );
}
function RunDuration({ start, end }: { start: string; end?: string }) {
  useVisibleClock(!end);
  return <>{elapsed(start, end)}</>;
}
function elapsed(start: string, end?: string) {
  if (!start || !Number.isFinite(Date.parse(start)))
    return "Duration unavailable";
  const seconds = Math.max(
    0,
    Math.floor(
      ((end ? Date.parse(end) : Date.now()) - Date.parse(start)) / 1000,
    ),
  );
  return seconds < 60
    ? `${seconds}s`
    : seconds < 3600
      ? `${Math.floor(seconds / 60)}m ${seconds % 60}s`
      : `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
function ScanControls({ scan, mutate }: { scan: Scan; mutate: Mutation }) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const active = activeScanStatus(scan.status),
    resumable = ["partial", "failed"].includes(scan.status);
  if (!active && !resumable) return null;
  return (
    <div className="scan-controls">
      <Button
        disabled={busy}
        primary={resumable}
        onClick={async () => {
          setBusy(true);
          setError("");
          const ok = await mutate(
            `scans/${scan.id}/${active ? "cancel" : "retry"}`,
            "POST",
            {},
            active ? "Scan canceled" : "Scan resumed from saved checkpoints",
          );
          if (!ok)
            setError(
              "The action could not be completed. Review the notification and try again.",
            );
          setBusy(false);
        }}
      >
        {busy ? (
          <Loader2 size={14} className="spin" />
        ) : active ? (
          <Square size={14} />
        ) : (
          <ArrowRight size={14} />
        )}{" "}
        {active ? "Cancel scan" : "Continue unfinished checks"}
      </Button>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
function ScanCoverage({ scan }: { scan: Scan }) {
  const coverage = scan.coverage;
  return (
    <div className="coverage-summary">
      <span>
        {scan.stages.filter((s) => s.status === "completed").length}/
        {scan.stages.length} stages finished
      </span>
      {coverage && (
        <>
          {coverage.portFinished > 0 && (
            <span>{coverage.portFinished} IP addresses fully checked</span>
          )}
          {coverage.portRemaining > 0 && (
            <span>
              {coverage.portRemaining} hosts with unfinished port checks
            </span>
          )}
          {coverage.crawlFinished + coverage.crawlRemaining > 0 && (
            <span>
              {coverage.crawlFinished}/
              {coverage.crawlFinished + coverage.crawlRemaining} crawl seeds
              finished · {coverage.crawlRemaining} remain
            </span>
          )}
        </>
      )}
      {coverage?.http ? (
        <span>
          {coverage.http.finished}/
          {coverage.http.finished + coverage.http.remaining} HTTP origins
          responded without blocking/server errors · {coverage.http.remaining}{" "}
          unchecked
        </span>
      ) : (
        <span>HTTP coverage counts not recorded for this run</span>
      )}
      {coverage?.detection ? (
        <span>
          {coverage.detection.finished}/
          {coverage.detection.finished + coverage.detection.remaining} required
          service/template checks finished
        </span>
      ) : (
        <span>Detection coverage counts not recorded for this run</span>
      )}
      {!!scan.excludedHosts?.length && (
        <span>
          {scan.excludedHosts.length} non-public hosts excluded by scope policy
        </span>
      )}
      <span>
        Counts describe the bounded profile, not exhaustive asset coverage.
      </span>
    </div>
  );
}

function Scans({
  canDelete,
  mutate,
  scans,
  select,
  run,
}: {
  canDelete: boolean;
  mutate: Mutation;
  scans: Scan[];
  select: (s: Scan) => void;
  run: () => void;
}) {
  const route = useWorkspaceRoute();
  const compiled = compileQuery(route.query, queryFields.scans);
  const rows = scans
    .filter(s => compiled.matches(scanDocument(s)))
    .slice()
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  const { page, setPage, start } = useResultPage(rows.length);
  const selectionKey = JSON.stringify([route.scope, route.query]);
  const selection = useRecordSelection(rows.filter(s => finishedScanStatus(s.status)).map(s => s.id), selectionKey);
  const visibleIDs = rows.slice(start, start + 25).filter(s => finishedScanStatus(s.status)).map(s => s.id);
  return (
    <>
      <QueryFilter view="scans" count={rows.length} />
      {canDelete && <>
        <BulkDeleteToolbar key={selectionKey} selection={selection} resource="scans" mutate={mutate} pageIDs={visibleIDs} />
        <div className="bulk-page-selection"><SelectionCheckbox label="Select all finished scans on this page" checked={visibleIDs.length > 0 && visibleIDs.every(id => selection.selected.has(id))} mixed={visibleIDs.some(id => selection.selected.has(id)) && !visibleIDs.every(id => selection.selected.has(id))} onChange={() => selection.togglePage(visibleIDs)} /><span>Select finished scans on this page. Active scans cannot be deleted.</span></div>
      </>}
      <div className="scan-list scan-history">
        {rows.slice(start, start + 25).map((scan) => {
          const problem = scan.stages.find(
            (stage) => stage.coverageStatus === "incomplete",
          );
          const current = scan.stages.find(
            (stage) => stage.status === "running",
          );
          return (
            <article className="scan-card scan-history-row" key={scan.id}>
              <div className="scan-history-identity">
                {canDelete && finishedScanStatus(scan.status) && <SelectionCheckbox label={`Select scan: ${scan.domain} · ${dateTime(scan.startedAt)}`} checked={selection.selected.has(scan.id)} onChange={() => selection.toggle(scan.id)} />}
                <button onClick={() => select(scan)} className="scan-domain">
                  {scan.domain}
                  <ArrowUpRight size={16} />
                </button>
                <p>
                  {scan.trigger} · {relative(scan.startedAt)} ·{" "}
                  <RunDuration start={scan.startedAt} end={scan.finishedAt} />
                  {scan.parentScanId ? " · Continued run" : ""}
                </p>
              </div>
              <div className="scan-history-outcome">
                <Badge
                  tone={
                    scan.status === "completed"
                      ? "success"
                      : ["partial", "failed"].includes(scan.status)
                        ? "warning"
                        : "neutral"
                  }
                >
                  {statusLabel(scan.status)}
                </Badge>
                <span>
                  {current
                    ? `${current.name} in progress`
                    : problem
                      ? `${problem.name}: checks remain`
                      : scanSummary(scan)}
                </span>
              </div>
              <div className="scan-history-counts">
                <span>{scan.assets} assets</span>
                <span>{scan.findings} observations</span>
              </div>
              <Button onClick={() => select(scan)}>
                {["partial", "failed"].includes(scan.status)
                  ? "Review & continue"
                  : "View scan"}
                <ArrowRight size={14} />
              </Button>
            </article>
          );
        })}
      </div>
      <Pagination total={rows.length} page={page} setPage={setPage} />
      {!rows.length && (
        <Empty
          title={
            !route.query
              ? "No scans recorded."
              : "No scans match this query."
          }
          description={
            !route.query
              ? "Start a scan to follow discovery, probing and detection."
              : "Clear the query to review existing assessments and recovery options."
          }
          action={
            <Button
              primary
              onClick={!route.query ? run : () => setWorkspaceQuery("")}
            >
              <Plus size={16} />
              {!route.query ? "Run a scan" : "View all scans"}
            </Button>
          }
        />
      )}
    </>
  );
}

type Mutation = (
  path: string,
  method: string,
  data?: unknown,
  message?: string,
) => Promise<boolean>;
function SettingsPage({
  access,
  settings,
  audit,
  mutate,
}: {
  access: State;
  settings: Settings;
  audit: State["audit"];
  mutate: Mutation;
}) {
  const canManage = access.me?.role === "owner";
  const [requestedTab, setTab] = useWorkspaceFilter("tab", "General");
  const tabs = ["General", "Scan controls", "Access", "MCP", "Webhooks", "Audit log"];
  const tab = tabs.includes(requestedTab) ? requestedTab : "General";
  const [form, setForm] = useState(settings),
    [busy, setBusy] = useState(false);
  return (
    <>
      <div className="tab-line">
        {tabs.map(
          (t) => (
            <button
              key={t}
              className={tab === t ? "tab-active" : ""}
              aria-current={tab === t ? "page" : undefined}
              onClick={() => setTab(t)}
            >
              {t}
            </button>
          ),
        )}
      </div>
      {tab === "Access" ? (
        <AccessPanel state={access} />
      ) : tab === "MCP" ? (
        <MCPPanel onOpenAccess={() => setTab("Access")} />
      ) : tab === "Webhooks" ? (
        <WebhooksPanel webhooks={access.webhooks || []} mutate={mutate} canManage={canManage} />
      ) : tab === "Audit log" ? (
        <>
          <div className="section-title audit-intro">
            <div>
              <h2>A record of every decision.</h2>
              <p>
                Workspace activity is recorded by the API. Entries cannot be
                edited through the app.
              </p>
            </div>
            <Button
              onClick={() =>
                exportCSV("audit", [
                  ["Action", "Detail", "Actor", "Time"],
                  ...audit.map((e) => [e.title, e.detail, e.actor, e.at]),
                ])
              }
            >
              <Download size={16} />
              Export log
            </Button>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Details</th>
                  <th>Actor</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <strong>{e.title}</strong>
                    </td>
                    <td>{e.detail}</td>
                    <td>{e.actor}</td>
                    <td>{dateTime(e.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <form
          className="settings-form"
          onSubmit={async (e) => {
            e.preventDefault();
            if (!canManage) return;
            setBusy(true);
            await mutate("settings", "PATCH", form, "Workspace settings saved");
            setBusy(false);
          }}
        >
          {tab === "General" ? (
            <>
              <section className="settings-section">
                <div>
                  <h2>Appearance</h2>
                  <p>
                    Choose a theme for this browser. System follows your device
                    settings.
                  </p>
                </div>
                <div>
                  <AppearanceControl />
                  <p className="field-hint">
                    Applies immediately and is saved locally. Workspace settings
                    are separate.
                  </p>
                </div>
              </section>
              <div className="settings-section">
                <div>
                  <h2>Workspace details</h2>
                  <p>The home for your team’s external surface.</p>
                </div>
                <div>
                  <label>
                    Workspace name
                    <input
                      className="text-input"
                      disabled={!canManage || busy}
                      value={form.name}
                      minLength={2}
                      maxLength={60}
                      required
                      onChange={(e) =>
                        setForm({ ...form, name: e.target.value })
                      }
                    />
                  </label>
                  <div className="settings-meta">
                    <span>Deployment</span>
                    <strong>Self-hosted · Single workspace</strong>
                  </div>
                  <div className="settings-meta">
                    <span>Your role</span>
                    <strong>{access.me?.role ?? "Unavailable"}</strong>
                  </div>
                </div>
              </div>
              <div className="settings-section">
                <div>
                  <h2>Data retention</h2>
                  <p>Keep raw evidence only as long as you need it.</p>
                </div>
                <label>
                  Evidence retention (days)
                  <input
                    className="text-input"
                    type="number"
                    min={1}
                    max={365}
                    disabled={!canManage || busy}
                    value={form.retention}
                    onChange={(e) =>
                      setForm({ ...form, retention: Number(e.target.value) })
                    }
                  />
                  <small>
                    Raw evidence objects are automatically removed after this
                    period. Finding summaries and audit records are retained.
                  </small>
                </label>
              </div>
            </>
          ) : (
            <>
              <div className="settings-section">
                <div>
                  <h2>Keep scans considerate</h2>
                  <p>Set a predictable request rate and concurrency cap.</p>
                </div>
                <div className="settings-input-grid">
                  <label>
                    Requests per second
                    <input
                      type="number"
                      min={1}
                      max={30}
                      className="text-input"
                      disabled={!canManage || busy}
                      value={form.rate}
                      onChange={(e) =>
                        setForm({ ...form, rate: Number(e.target.value) })
                      }
                    />
                    <small>Hard cap: 30 requests per second.</small>
                  </label>
                  <label>
                    Concurrent hosts
                    <input
                      type="number"
                      min={1}
                      max={10}
                      className="text-input"
                      disabled={!canManage || busy}
                      value={form.concurrency}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          concurrency: Number(e.target.value),
                        })
                      }
                    />
                    <small>Between 1 and 10 hosts.</small>
                  </label>
                </div>
              </div>
              <div className="settings-section">
                <div>
                  <h2>Workspace kill switch</h2>
                  <p>
                    Pause scheduling and stop all running scans immediately.
                  </p>
                </div>
                <div className="pause-control">
                  <div>
                    <strong>
                      {form.paused
                        ? "Scanning is paused"
                        : "Scanning is available"}
                    </strong>
                    <p>
                      {form.paused
                        ? "New scans are blocked until you resume."
                        : "Scans follow the configured domain scope policy."}
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={!canManage || busy}
                    role="switch"
                    aria-checked={form.paused}
                    aria-label="Pause workspace scanning"
                    className={`toggle-switch ${form.paused ? "toggle-active" : ""}`}
                    onClick={() => setForm({ ...form, paused: !form.paused })}
                  >
                    <span />
                  </button>
                </div>
              </div>
              <div className="settings-section">
                <div>
                  <h2>Built-in scope controls</h2>
                  <p>Scope and scanner safeguards are enforced by the API and gateway.</p>
                </div>
                <ul className="safety-list">
                  <li>
                    <Check size={16} />
                    {access.runtime?.verificationRequired !== false ? "DNS ownership verification required" : "DNS ownership verification optional"}
                  </li>
                  <li>
                    <Check size={16} />
                    Private and metadata destinations blocked at dial time
                  </li>
                  <li>
                    <Check size={16} />
                    No intrusive, fuzz or denial-of-service templates
                  </li>
                  <li>
                    <Check size={16} />
                    All scan and triage actions audited
                  </li>
                </ul>
              </div>
            </>
          )}
          <div className="settings-save">
            <span>{canManage ? "Rate, concurrency, and retention changes apply to future scans; pausing stops active scans." : "Only owners can change workspace settings. Appearance is saved for this browser."}</span>
            <Button primary type="submit" disabled={busy || !canManage}>
              {busy ? (
                <Loader2 className="spin" size={16} />
              ) : (
                <Check size={16} />
              )}
              Save changes
            </Button>
          </div>
        </form>
      )}
    </>
  );
}

function AddTarget({
  verificationRequired,
  onClose,
  onAdded,
}: {
  verificationRequired: boolean;
  onClose: () => void;
  onAdded: (t: Target) => void;
}) {
  const [domain, setDomain] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <Modal title="Bring your domain into view." onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError("");
          try {
            const t = await api("targets", "POST", { domain });
            onAdded(t);
          } catch (err) {
            setError((err as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <p className="modal-lead">
          {verificationRequired
            ? "Add a root domain and verify ownership with a DNS TXT record."
            : "Add a root domain to scan its public services. DNS ownership verification is optional."}
        </p>
        <label>
          Root domain
          <input
            autoFocus
            className="text-input"
            placeholder="company.com"
            value={domain}
            required
            onChange={(e) => setDomain(e.target.value)}
            maxLength={253}
          />
        </label>
        <p className="field-hint">
          Use the root domain, without https:// or a path.
        </p>
        <div className="modal-safety">
          <ShieldCheck size={20} />
          <p>
            Adding a target does not start a scan.{" "}
            {verificationRequired
              ? "Verify the domain first, then start a scan."
              : "Start a scan when you are ready."}
          </p>
        </div>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <Button onClick={onClose}>Cancel</Button>
          <Button primary type="submit" disabled={busy}>
            {busy ? <Loader2 size={16} className="spin" /> : <Plus size={16} />}
            Add domain
          </Button>
        </div>
      </form>
    </Modal>
  );
}
function RunScan({
  state,
  verificationRequired,
  targets,
  onClose,
  onRun,
}: {
  state: State;
  verificationRequired: boolean;
  targets: Target[];
  onClose: () => void;
  onRun: (id: string) => Promise<void>;
}) {
  const [id, setID] = useState(targets.find((t) => t.canScan)?.id ?? ""),
    [busy, setBusy] = useState(false);

  const unavailable =
    state.me?.role === "viewer"
      ? "A workspace analyst or owner can start scans."
      : state.settings.paused
        ? "Workspace scanning is paused. An owner can enable it in Settings."
        : !state.runtime?.liveScanning
          ? "Live scanning is unavailable in this environment."
          : state.scans.some(
                (scan) => scan.targetId === id && activeScanStatus(scan.status),
              )
            ? "This target already has an active scan. Follow it in Scan activity."
            : state.runtime.workers === 0
              ? "No worker is online. This scan will wait in the queue until a worker is available."
              : "";
  const blocked =
    state.settings.paused ||
    !state.runtime?.liveScanning ||
    state.me?.role === "viewer" ||
    state.scans.some(
      (scan) => scan.targetId === id && activeScanStatus(scan.status),
    );
  return (
    <Modal title="Start a scoped assessment" onClose={onClose}>
      <p className="modal-lead">
        Select a domain to start discovery and check for exposures.
      </p>
      <label>
        Target
        <select
          className="text-input"
          value={id}
          onChange={(e) => setID(e.target.value)}
        >
          {!id && <option value="">No eligible targets available</option>}
          {targets
            .filter((t) => t.canScan)
            .map((t) => (
              <option value={t.id} key={t.id}>
                {t.domain}
              </option>
            ))}
        </select>
      </label>
      <section className="scan-preflight" aria-label="Scan configuration">
        <h3>Bounded assessment profile</h3>
        <p>
          Maximum {state.settings.rate} requests/s · concurrency{" "}
          {state.settings.concurrency} · up to 60 minutes of worker execution.
        </p>
        <p>
          Curated HTTP checks, scoped crawling and public JavaScript analysis.
          This does not establish exhaustive vulnerability coverage.
        </p>
        {unavailable && (
          <p className={blocked ? "form-error" : "stage-issue"} role="status">
            {unavailable}
          </p>
        )}
      </section>
      <div className="modal-safety">
        <Radar size={22} />
        <p>
          {verificationRequired
            ? "Your DNS ownership proof is rechecked before scanning."
            : "DNS verification is optional."}{" "}
          An isolated worker discovers services, crawls endpoints, analyzes
          public JavaScript for potential secrets, and runs signed, curated HTTP
          templates.
        </p>
      </div>
      <div className="modal-actions">
        <Button onClick={onClose}>Cancel</Button>
        <Button
          primary
          disabled={!id || busy || blocked}
          onClick={async () => {
            setBusy(true);
            await onRun(id);
            setBusy(false);
          }}
        >
          {busy ? <Loader2 className="spin" size={16} /> : <Radar size={16} />}
          Start scan
        </Button>
      </div>
    </Modal>
  );
}
function TargetDetail({
  verificationRequired,
  target,
  onClose,
  mutate,
  notify,
}: {
  verificationRequired: boolean;
  target: Target;
  onClose: () => void;
  mutate: Mutation;
  notify: (s: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      notify("DNS value copied");
    } catch {
      notify("Copy unavailable. Select and copy the record manually.");
    }
  }
  return (
    <Modal title={target.domain} onClose={onClose}>
      <div className="detail-status">
        <Badge tone={target.status === "verified" ? "success" : "neutral"}>
          {target.status}
        </Badge>
      </div>
      <p className="modal-lead">
        {verificationRequired
          ? "Publish this TXT record with your DNS provider, then check ownership."
          : "This target is ready to scan. You may optionally publish this TXT record to verify DNS ownership."}
      </p>
      <div className="dns-record">
        <span>
          Record type<strong>TXT</strong>
        </span>
        <span>
          Record name<strong>_surfacer.{target.domain}</strong>
          <button
            aria-label="Copy DNS record name"
            onClick={() => void copy("_surfacer." + target.domain)}
          >
            <Copy size={16} />
          </button>
        </span>
        <span>
          Record value<strong className="dns-token">{target.token}</strong>
          <button
            aria-label="Copy DNS record value"
            onClick={() => void copy(target.token)}
          >
            <Copy size={16} />
          </button>
        </span>
      </div>
      <p className="field-hint">
        DNS propagation may take a few minutes. Keep the record published to
        maintain verification.
      </p>
      <div className="modal-actions">
        <Button onClick={onClose}>Close</Button>
        {
          <Button
            primary
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              await mutate(
                `targets/${target.id}/verify`,
                "POST",
                {},
                "Ownership verified",
              );
              setBusy(false);
            }}
          >
            {busy ? (
              <Loader2 className="spin" size={16} />
            ) : (
              <ShieldCheck size={16} />
            )}
            Check verification
          </Button>
        }
      </div>
    </Modal>
  );
}
function expiryLabel(raw: string) {
  const date = Date.parse(raw);
  if (!Number.isFinite(date)) return "Not observed";
  const days = Math.ceil((date - Date.now()) / 86400000);
  return `${days <= 0 ? "Expired" : `Expires in ${days} days`} · ${dateTime(raw)}`;
}
function AssetDetail({
  asset,
  findings,
  onClose,
  selectFinding,
}: {
  asset: Asset;
  findings: Finding[];
  onClose: () => void;
  selectFinding: (id: string) => void;
}) {
  return (
    <Modal title={asset.host} onClose={onClose} wide>
      <div className="detail-status">
        <Badge>{asset.type}</Badge>
        <span>{probeLabel(asset)}</span>
      </div>
      <div className="inline-actions">
        <CopyValue value={asset.host} label="hostname" />
        {asset.ip && <CopyValue value={asset.ip} label="IP address" />}
      </div>
      {asset.title && <p className="modal-lead">{asset.title}</p>}
      <dl className="detail-grid host-facts">
        <div>
          <dt>Resolved IP</dt>
          <dd>{asset.ip || "Not resolved"}</dd>
        </div>
        <div>
          <dt>Open ports observed</dt>
          <dd>{asset.ports.join(", ") || "None observed"}</dd>
        </div>
        <div>
          <dt>First discovered</dt>
          <dd>{dateTime(asset.firstSeen)}</dd>
        </div>
        <div>
          <dt>Last observed</dt>
          <dd>{dateTime(asset.lastSeen)}</dd>
        </div>
        <div>
          <dt>Discovery sources</dt>
          <dd>{asset.source || "Not recorded"}</dd>
        </div>
        <div>
          <dt>Assessment context</dt>
          <dd>
            Observations may come from a partial scan. Absence of a finding is
            not proof of a completed check.
          </dd>
        </div>
      </dl>
      <section className="service-inventory">
        <h3>
          Observed services <span>{asset.services?.length || 0}</span>
        </h3>
        {asset.services?.length ? (
          asset.services.map((svc) => (
            <article className="service-record" key={svc.url}>
              <header>
                <strong>{svc.url}</strong>
                <CopyValue value={svc.url} label="service URL" />
              </header>
              <dl>
                <div>
                  <dt>HTTP observation</dt>
                  <dd>
                    {svc.status ? `HTTP ${svc.status}` : "No response recorded"}
                  </dd>
                </div>
                <div>
                  <dt>Page title</dt>
                  <dd>{svc.title || "Not identified"}</dd>
                </div>
                <div>
                  <dt>TLS version</dt>
                  <dd>{svc.tlsVersion || "Not observed"}</dd>
                </div>
                <div>
                  <dt>Cipher</dt>
                  <dd>{svc.cipher || "Not observed"}</dd>
                </div>
                <div>
                  <dt>Certificate issuer</dt>
                  <dd>{svc.issuer || "Not observed"}</dd>
                </div>
                <div>
                  <dt>Certificate expiry</dt>
                  <dd
                    className={
                      svc.certificateExpiry &&
                      Date.parse(svc.certificateExpiry) < Date.now()
                        ? "text-warning"
                        : ""
                    }
                  >
                    {expiryLabel(svc.certificateExpiry || "")}
                  </dd>
                </div>
                <div>
                  <dt>Certificate names</dt>
                  <dd>{svc.certificateNames?.join(", ") || "Not observed"}</dd>
                </div>
                <div>
                  <dt>Trust observations</dt>
                  <dd>
                    {[
                      svc.selfSigned && "Self-signed",
                      svc.mismatched && "Name mismatch",
                      svc.untrusted && "Untrusted chain",
                    ]
                      .filter(Boolean)
                      .join(" · ") ||
                      "No trust issue recorded; verify assessment coverage"}
                  </dd>
                </div>
              </dl>
            </article>
          ))
        ) : (
          <p className="empty-inline">
            No web service response was recorded. Review scan coverage before
            treating this host as inactive.
          </p>
        )}
      </section>
      {asset.tls && !asset.services?.some((s) => s.certificateExpiry) && (
        <p className="observation-note">
          Host certificate observation: {expiryLabel(asset.tls)}
        </p>
      )}
      <h3 className="detail-section-title">Detected technologies</h3>
      {asset.technologies.length ? (
        <div className="tech-chips detail-tech">
          {asset.technologies.map((t) => (
            <span key={t}>{t}</span>
          ))}
        </div>
      ) : (
        <p className="empty-inline">No technologies identified.</p>
      )}
      <h3 className="detail-section-title">
        Findings on this asset <span>{findings.length}</span>
      </h3>
      {findings.map((f) => (
        <button
          key={f.id}
          className="asset-finding-row"
          onClick={() => selectFinding(f.id)}
        >
          <span>
            <strong>{f.title}</strong>
            <small>
              {f.matchedAt || f.host} · {statusLabel(f.status)}
            </small>
          </span>
          <Severity value={f.severity} />
          <ChevronRight size={16} />
        </button>
      ))}
      {!findings.length && (
        <p className="empty-inline">
          No findings recorded. Review scan coverage to see which checks
          finished.
        </p>
      )}
      <p className="evidence-scope-note">
        Non-public destinations are listed but excluded from active scanning.
        Endpoint and finding history is retained when coverage is incomplete.
      </p>
    </Modal>
  );
}
function FindingDetail({
  finding,
  associatedAsset,
  onClose,
  mutate,
}: {
  finding: Finding;
  associatedAsset?: Asset;
  onClose: () => void;
  mutate: Mutation;
}) {
  const [evidence, setEvidence] = useState(false),
    [status, setStatus] = useState(
      finding.status === "resolved" ? "open" : finding.status,
    ),
    [note, setNote] = useState(""),
    [busy, setBusy] = useState(false);
  const [decisionError, setDecisionError] = useState("");
  return (
    <Modal title={finding.title} onClose={onClose} wide>
      <div className="detail-status">
        <Severity value={finding.severity} />
        {finding.category && (
          <span className="badge badge-accent">
            {finding.category.toUpperCase()}
          </span>
        )}
        <Badge tone={finding.status === "resolved" ? "success" : "neutral"}>
          {finding.status}
        </Badge>
        <span>{finding.host}</span>
        {finding.port && (
          <span>
            Port {finding.port}/{finding.protocol || "tcp"}
          </span>
        )}
      </div>
      <div className="finding-description">
        <div className="finding-origin">
          <span>Affected service / origin</span>
          <code>{finding.matchedAt || finding.host}</code>
          <CopyValue
            value={finding.matchedAt || finding.host}
            label="affected service"
          />
        </div>
        <h3>Why this matched</h3>
        <p>{finding.description}</p>
        {finding.dependency && (
          <p className="field-hint">
            Observed library: {finding.dependency.name} {finding.dependency.version} · {finding.dependency.detection}.
            Advisory snapshot: <code>{finding.dependency.database}</code>. Exploit reachability has not been tested.
          </p>
        )}
        <h3>How to fix it</h3>
        <p>{finding.remediation}</p>
      </div>
      <dl className="detail-grid">
        <div>
          <dt>Category</dt>
          <dd>
            {finding.category
              ? finding.category.charAt(0).toUpperCase() +
                finding.category.slice(1)
              : "Vulnerability"}
          </dd>
        </div>
        <div>
          <dt>Target host</dt>
          <dd>{finding.host}</dd>
        </div>
        <div>
          <dt>Resolved IP</dt>
          <dd>{finding.ip || associatedAsset?.ip || "Pending DNS"}</dd>
        </div>
        <div>
          <dt>Target port</dt>
          <dd>
            {finding.port
              ? `${finding.port} / ${(finding.protocol || "tcp").toUpperCase()}`
              : associatedAsset?.ports?.length
                ? associatedAsset.ports.join(", ")
                : "—"}
          </dd>
        </div>
        <div>
          <dt>Template ID</dt>
          <dd>
            <code>{finding.template}</code>
          </dd>
        </div>
        <div>
          <dt>Discovery stage</dt>
          <dd>{finding.stageName || "Detection"}</dd>
        </div>
        <div>
          <dt>Scanner tool</dt>
          <dd>{finding.tool || "nuclei"}</dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd>{dateTime(finding.firstSeen)}</dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>{dateTime(finding.lastSeen)}</dd>
        </div>
        <div>
          <dt>Vulnerability identifiers</dt>
          <dd>{[...(finding.cves ?? []), ...(finding.cwes ?? [])].join(", ") || "Not supplied"}</dd>
        </div>
        <div>
          <dt>CVSS supplied by scanner</dt>
          <dd>{finding.cvssScore !== undefined ? finding.cvssScore.toFixed(1) : "Not supplied"}{finding.cvssMetrics && <><br /><code>{finding.cvssMetrics}</code></>}</dd>
        </div>
        <div>
          <dt>Evidence handling</dt>
          <dd>Secrets redacted</dd>
        </div>
      </dl>

      {finding.parameters && finding.parameters.length > 0 && (
        <div className="pentester-section">
          <h4>Route Parameters Identified ({finding.parameters.length})</h4>
          <div className="param-chips-wrap">
            {finding.parameters.map((p) => (
              <span key={p} className="param-chip">
                <code>{p}</code>
              </span>
            ))}
          </div>
        </div>
      )}

      {((finding.technologies && finding.technologies.length > 0) ||
        (associatedAsset?.technologies &&
          associatedAsset.technologies.length > 0)) && (
        <div className="pentester-section">
          <h4>Technologies Detected on Host</h4>
          <div className="param-chips-wrap">
            {(finding.technologies || associatedAsset?.technologies || []).map(
              (t) => (
                <span key={t} className="badge badge-neutral">
                  {t}
                </span>
              ),
            )}
          </div>
        </div>
      )}

      {associatedAsset &&
        associatedAsset.ports &&
        associatedAsset.ports.length > 0 && (
          <div className="pentester-section">
            <h4>All Open Ports on Host ({associatedAsset.ports.length})</h4>
            <div className="param-chips-wrap">
              {associatedAsset.ports.map((p) => (
                <span
                  key={p}
                  className={`port-chip ${finding.port === p ? "port-chip-active" : ""}`}
                >
                  {p}/tcp
                </span>
              ))}
            </div>
          </div>
        )}
      {(finding.stepLog || finding.stageName) && (
        <div className="pentester-section scan-log-section">
          <div className="scan-log-header">
            <h4>Scan Step Execution &amp; Success Log</h4>
            <span
              className={`badge ${finding.stepSuccess !== false ? "badge-success" : "badge-neutral"}`}
            >
              {finding.stepSuccess !== false
                ? "Step Succeeded"
                : "Step Executed"}
            </span>
          </div>
          <div className="scan-step-meta">
            {finding.stageName && (
              <span>
                <strong>Stage:</strong> {finding.stageName}
              </span>
            )}
            {finding.tool && (
              <span>
                <strong>Tool:</strong> {finding.tool}
              </span>
            )}
            {finding.scanId && (
              <span>
                <strong>Scan ID:</strong> <code>{finding.scanId}</code>
              </span>
            )}
          </div>
          {finding.stepLog ? (
            <pre className="step-log-output">{finding.stepLog}</pre>
          ) : (
            <p className="field-hint">
              Observations validated and committed during{" "}
              {finding.stageName || "scanning"} pass.
            </p>
          )}
        </div>
      )}
      <button
        className="evidence-toggle"
        aria-expanded={evidence}
        onClick={() => setEvidence(!evidence)}
      >
        <Code2 size={18} />
        Redacted scanner evidence
        <ChevronDown size={17} className={evidence ? "rotate-180" : ""} />
      </button>
      {evidence && <pre className="evidence-block">{finding.evidence}</pre>}
      <div className="triage-form">
        <h3>Make a triage decision</h3>
        <div className="triage-status">
          <label>
            Status
            <select
              className="text-input"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="accepted risk">Accepted risk</option>
              <option value="false positive">False positive</option>
            </select>
          </label>
          <span>
            Resolution requires two successful scans with the finding absent.
          </span>
        </div>
        <label>
          Decision note{" "}
          <span className="field-hint">Required · at least 3 characters</span>
          <textarea
            className="text-input"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Add context for your team…"
            minLength={3}
            maxLength={2000}
            rows={3}
            required
            aria-describedby="decision-note-hint"
          />
        </label>
        <p id="decision-note-hint" className="field-hint">
          Explain this decision for your team. Your note remains here if saving
          fails.
        </p>
        {decisionError && (
          <p className="form-error" role="alert">
            {decisionError}
          </p>
        )}
        <div className="triage-save">
          <Button
            primary
            disabled={busy || note.trim().length < 3}
            onClick={async () => {
              setBusy(true);
              setDecisionError("");
              if (
                await mutate(
                  `findings/${finding.id}`,
                  "PATCH",
                  { status, note },
                  "Finding updated and decision recorded",
                )
              )
                setNote("");
              else
                setDecisionError(
                  "The decision could not be saved. Review the notification and try again; your note has been retained.",
                );
              setBusy(false);
            }}
          >
            {busy ? (
              <Loader2 size={16} className="spin" />
            ) : (
              <Check size={16} />
            )}
            Save decision
          </Button>
        </div>
      </div>
      {finding.notes.length > 0 && (
        <div className="decision-history">
          <h3>Decision history</h3>
          {finding.notes.map((n, i) => (
            <div key={i}>
              <strong>
                {n.actor}
                <small>{relative(n.at)}</small>
              </strong>
              <p>{n.text}</p>
            </div>
          ))}
        </div>
      )}
    </Modal>
  );
}
function ScanDetail({
  scan,
  onClose,
  mutate,
  canManage,
}: {
  scan: Scan;
  onClose: () => void;
  mutate: Mutation;
  canManage: boolean;
}) {
  return (
    <Modal title={`Scan · ${scan.domain}`} onClose={onClose} wide>
      <div className="detail-status">
        <Badge
          tone={
            ["partial", "failed"].includes(scan.status)
              ? "warning"
              : scan.status === "completed"
                ? "success"
                : "neutral"
          }
        >
          {statusLabel(scan.status)}
        </Badge>
        <span>
          {scan.trigger} · configured maximum {scan.rate} requests/s
        </span>
      </div>
      <p className="scan-outcome">{scanSummary(scan)}</p>
      <ScanCoverage scan={scan} />
      {!!scan.coverage?.serviceIssues?.length && (
        <section
          className="service-issues"
          aria-label="Services with incomplete checks"
        >
          <h3>Services that need another pass</h3>
          <ul>
            {scan.coverage.serviceIssues.map((issue) => (
              <li key={issue.origin}>
                <code>{issue.origin}</code>
                <span>
                  {(
                    {
                      forbidden: "HTTP 403 · access denied",
                      rate_limited: "HTTP 429 · rate limited",
                      server_error: "Server error",
                      failed: "Request failed",
                      unfinished: "No completed response",
                    } as Record<string, string>
                  )[issue.reason] ?? issue.reason}
                </span>
              </li>
            ))}
          </ul>
          {(scan.coverage.serviceIssueCount ?? 0) >
            scan.coverage.serviceIssues.length && (
            <p>
              Showing {scan.coverage.serviceIssues.length} of{" "}
              {scan.coverage.serviceIssueCount} affected origins.
            </p>
          )}
        </section>
      )}
      {scan.resume && (
        <section className="resume-preview" aria-label="Continuation plan">
          <h3>Continue from {scan.resume.fromStage}</h3>
          <p>
            {scan.resume.retainedStages} earlier stage passes retained ·{" "}
            {scan.resume.repeatedStages} stage passes run again.
          </p>
          <p>{scan.resume.checkpointPolicy}</p>
          <p>
            A new run keeps this attempt in history. Availability and target
            authorization are checked again when you continue.
          </p>
        </section>
      )}
      {scan.parentScanId && (
        <button
          className="text-action"
          onClick={() => openWorkspaceDetail("scan", scan.parentScanId!)}
        >
          View previous attempt <ArrowUpRight size={14} />
        </button>
      )}
      {canManage ? (
        <ScanControls scan={scan} mutate={mutate} />
      ) : (
        <p className="field-hint">An analyst or owner can manage scans.</p>
      )}
      {scan.error && (
        <details className="scan-diagnostic">
          <summary>Technical reason</summary>
          <p>{scan.error}</p>
        </details>
      )}
      <div className="stage-list">
        {scan.stages.map((st) => {
          const status =
            st.status === "completed" && st.coverageStatus === "incomplete"
              ? "incomplete"
              : stageStatus(scan, st.status);
          return (
            <section className={`stage-detail stage-${status}`} key={st.name}>
              <span>
                {status === "completed" ? (
                  <Check size={18} />
                ) : status === "running" ? (
                  <Loader2 size={18} className="spin" />
                ) : status === "interrupted" || status === "incomplete" ? (
                  <TriangleAlert size={18} />
                ) : (
                  <Clock3 size={18} />
                )}
              </span>
              <div>
                <strong>{st.name}</strong>
                <small>
                  {st.tool}
                  {st.attempts ? ` · attempt ${st.attempts}` : ""}
                </small>
                {st.startedAt && (
                  <small>
                    <RunDuration
                      start={st.startedAt}
                      end={st.finishedAt || scan.finishedAt}
                    />{" "}
                    ·{" "}
                    {st.finishedAt
                      ? "Pass finished"
                      : activeScanStatus(scan.status)
                        ? "Elapsed"
                        : "Interrupted"}
                  </small>
                )}
                {st.issue && (
                  <p className="stage-issue">
                    {st.status !== "completed" ? "Previous pass: " : ""}
                    {st.issue}
                  </p>
                )}
                {st.log && (
                  <details className="stage-diagnostics">
                    <summary>Technical log</summary>
                    <pre className="stage-log">{st.log}</pre>
                  </details>
                )}
              </div>
              <Badge tone={status === "incomplete" ? "warning" : "neutral"}>
                {status === "incomplete"
                  ? "Finished with gaps"
                  : status === "completed"
                    ? "Pass finished"
                    : statusLabel(status)}
              </Badge>
            </section>
          );
        })}
      </div>
      <dl className="detail-grid">
        <div>
          <dt>Started</dt>
          <dd>{dateTime(scan.startedAt)}</dd>
        </div>
        <div>
          <dt>Finished</dt>
          <dd>
            {scan.finishedAt ? dateTime(scan.finishedAt) : "Not finished"}
          </dd>
        </div>
        <div>
          <dt>Worker</dt>
          <dd>{scan.worker || "Not assigned"}</dd>
        </div>
        <div>
          <dt>Curated template set</dt>
          <dd>{scan.templateSet || "Not recorded"}</dd>
        </div>
      </dl>
      <div className="modal-actions">
        <Button onClick={onClose}>Close</Button>
      </div>
    </Modal>
  );
}
function Auth({ onSuccess }: { onSuccess: () => Promise<void> }) {
  const [token, setToken] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  return (
    <div className="auth-screen">
      <div className="auth-appearance">
        <AppearanceControl compact />
      </div>
      <Brand />
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            const res = await fetch("/api/session", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ token }),
            });
            const body = await res.json();
            if (!res.ok) throw new Error(body.error);
            await onSuccess();
          } catch (err) {
            setError((err as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="empty-icon">
          <LockKeyhole size={28} />
        </div>
        <h1>Your surface awaits.</h1>
        <p>Enter your workspace access token to continue.</p>
        <label>
          Workspace access token
          <input
            className="text-input"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            required
            autoFocus
          />
        </label>
        {error && (
          <p role="alert" className="form-error">
            {error}
          </p>
        )}
        <Button primary type="submit" disabled={busy}>
          {busy ? (
            <Loader2 size={16} className="spin" />
          ) : (
            <ArrowRight size={16} />
          )}
          Open workspace
        </Button>
      </form>
    </div>
  );
}

function AccessPanel({ state }: { state: State }) {
  const [name, setName] = useState("");
  const [role, setRole] = useState("viewer");
  const [token, setToken] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const owner = state.me?.role === "owner";
  async function action(path: string, method: string, data: unknown) {
    setBusy(true);
    setMessage("");
    try {
      const result = await api(path, method, data);
      if (result.token) setToken(result.token);
      setMessage("Access updated");
    } catch (error) {
      setMessage(
        error instanceof Error ? error.message : "Access update failed",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="settings-form">
      <div className="section-title">
        <div>
          <h2>Workspace access</h2>
          <p>
            Individual roles and expiring keys. Keys are shown once and stored
            as hashes.
          </p>
        </div>
      </div>
      {owner && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void action("members", "POST", { name, role });
          }}
          className="settings-section"
        >
          <label>
            Member name
            <input
              className="text-input"
              required
              minLength={2}
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label>
            Role
            <select
              className="filter-select"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="viewer">Viewer · read only</option>
              <option value="analyst">Analyst · scans and findings</option>
              <option value="owner">Owner · workspace administration</option>
            </select>
          </label>
          <Button type="submit" disabled={busy}>
            Create member
          </Button>
        </form>
      )}
      {token && (
        <div role="status" className="settings-section">
          <div>
            <h2>Copy this access key now</h2>
            <p>
              Use this key on the sign-in screen or as a Bearer token. The
              initial key expires in seven days.
            </p>
            <code style={{ overflowWrap: "anywhere" }}>{token}</code>
          </div>
          <Button onClick={() => setToken("")}>Dismiss key</Button>
        </div>
      )}
      {message && <p role="status">{message}</p>}
      {owner && (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Member</th>
                <th>Role</th>
                <th>Status</th>
                <th>Access</th>
              </tr>
            </thead>
            <tbody>
              {!state.members?.length && (
                <tr>
                  <td colSpan={4}>
                    No members yet. Create one to issue individual access.
                  </td>
                </tr>
              )}
              {(state.members ?? []).map((m) => (
                <tr key={m.id}>
                  <td>{m.name}</td>
                  <td>
                    <select
                      aria-label={`Role for ${m.name}`}
                      value={m.role}
                      onChange={(e) =>
                        void action(`members/${m.id}`, "PATCH", {
                          role: e.target.value,
                          enabled: m.enabled,
                        })
                      }
                    >
                      <option>viewer</option>
                      <option>analyst</option>
                      <option>owner</option>
                    </select>
                  </td>
                  <td>{m.enabled ? "Enabled" : "Disabled"}</td>
                  <td>
                    <Button
                      disabled={busy}
                      onClick={() =>
                        void action(`members/${m.id}`, "PATCH", {
                          role: m.role,
                          enabled: !m.enabled,
                        })
                      }
                    >
                      {m.enabled ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      disabled={busy}
                      onClick={() =>
                        void action("api-keys", "POST", {
                          userId: m.id,
                          name: "Member access",
                          days: 7,
                        })
                      }
                    >
                      Issue 7-day key
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Key</th>
              <th>Expires</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {!state.accessKeys?.length && (
              <tr>
                <td colSpan={4}>No member keys issued.</td>
              </tr>
            )}
            {(state.accessKeys ?? []).map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td>{dateTime(k.expiresAt)}</td>
                <td>
                  {k.revoked
                    ? "Revoked"
                    : Date.parse(k.expiresAt) <= Date.now()
                      ? "Expired"
                      : "Issued"}
                </td>
                <td>
                  <Button
                    disabled={busy || k.revoked}
                    onClick={() =>
                      void action(`api-keys/${k.id}/revoke`, "POST", {})
                    }
                  >
                    Revoke
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
