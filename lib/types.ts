export type Target = {
  id: string;
  domain: string;
  status: string;
  token: string;
  schedule: string;
  lastScan: string;
  assets: number;
  lastVerified?: string;
  canScan: boolean;
};
export type Endpoint = {
  targetId?: string;
  historical?: boolean;
  id: string;
  url: string;
  method: string;
  status: number;
  kind: string;
  source: string;
  parameters: string[];
  firstSeen: string;
  lastSeen: string;
  missingScans: number;
  removed: boolean;
};
export type Asset = {
  probeStatus?: string;
  endpoints?: Endpoint[];
  services?: {
    url: string;
    port: number;
    status: number;
    title: string;
    technologies: string[];
    tlsVersion?: string;
    cipher?: string;
    certificateExpiry?: string;
    issuer?: string;
    certificateNames?: string[];
    selfSigned?: boolean;
    mismatched?: boolean;
    untrusted?: boolean;
  }[];
  id: string;
  host: string;
  type: string;
  ip: string;
  status: number;
  technologies: string[];
  ports: number[];
  findings: number;
  severity: string;
  firstSeen: string;
  lastSeen: string;
  tls: string;
  source: string;
  targetId: string;
  title: string;
  url?: string;
  blocked?: boolean;
  removed?: boolean;
};
export type Finding = {
  id: string;
  matchedAt?: string;
  title: string;
  severity: string;
  host: string;
  status: string;
  template: string;
  firstSeen: string;
  lastSeen: string;
  description: string;
  remediation: string;
  evidence: string;
  notes: { text: string; at: string; actor: string }[];
  category?:
    | "vulnerability"
    | "port"
    | "endpoint"
    | "hazard"
    | "secret"
    | "host"
    | string;
  port?: number;
  protocol?: string;
  method?: string;
  parameters?: string[];
  stageName?: string;
  tool?: string;
  technologies?: string[];
  ip?: string;
  scanId?: string;
  stepLog?: string;
  stepSuccess?: boolean;
};
export type Scan = {
  parentScanId?: string;
  resume?: {
    fromStage: string;
    retainedStages: number;
    repeatedStages: number;
    checkpointPolicy: string;
  };
  concurrency?: number;
  coverage?: {
    http?: { finished: number; remaining: number };
    detection?: { finished: number; remaining: number };
    serviceIssues?: { origin: string; reason: string }[];
    serviceIssueCount?: number;
    crawlFinished: number;
    crawlRemaining: number;
    portFinished: number;
    portRemaining: number;
  };
  excludedHosts?: string[];
  id: string;
  targetId: string;
  domain: string;
  status: string;
  trigger: string;
  startedAt: string;
  finishedAt: string;
  progress: number;
  stages: {
    coverageStatus?: "finished" | "incomplete" | "unknown";
    issue?: string;
    startedAt?: string;
    finishedAt?: string;
    name: string;
    status: string;
    tool: string;
    log?: string;
    attempts?: number;
  }[];
  assets: number;
  findings: number;
  rate: number;
  error?: string;
  worker?: string;
  toolVersions?: Record<string, string>;
  templateSet?: string;
};
export type Event = {
  id: string;
  kind: string;
  title: string;
  detail: string;
  at: string;
  actor: string;
};
export type Settings = {
  name: string;
  rate: number;
  concurrency: number;
  retention: number;
  paused: boolean;
};
export type MXRecord = {
  host: string;
  pref: number;
  ips?: string[];
};
export type DomainDNSPosture = {
  id: string;
  scanId: string;
  domain: string;
  spfRecord: string;
  spfStatus: "secure" | "softfail" | "permissive" | "missing";
  dmarcRecord: string;
  dmarcPolicy: "reject" | "quarantine" | "none" | "missing";
  dkimDetected: boolean;
  mxRecords: MXRecord[];
  createdAt: string;
};
export type SubdomainTakeover = {
  id: string;
  scanId: string;
  subdomain: string;
  cname: string;
  serviceProvider: string;
  status: "open" | "resolved" | "suppressed";
  firstSeen: string;
  lastSeen: string;
  reopenCount: number;
  missingScans?: number;
};
export type EndpointHazard = {
  id: string;
  scanId: string;
  url: string;
  parameter: string;
  hazardClass:
    | "ssrf_candidate"
    | "redirect_candidate"
    | "lfi_candidate"
    | "sqli_candidate"
    | "debug_flag"
    | "sensitive_file";
  severity: "critical" | "high" | "medium" | "low";
  createdAt: string;
};
export type NotificationWebhook = {
  id: string;
  url: string;
  webhookType: "slack" | "discord" | "generic";
  enabled: boolean;
  notifyOnNewAssets: boolean;
  notifyOnNewPorts: boolean;
  notifyOnHighFindings: boolean;
  notifyOnTakeovers: boolean;
  createdAt: string;
};
export type State = {
  history?: Endpoint[];
  me?: { id: string; name: string; role: string };
  members?: { id: string; name: string; role: string; enabled: boolean }[];
  accessKeys?: {
    id: string;
    name: string;
    userId: string;
    expiresAt: string;
    revoked: boolean;
  }[];
  targets: Target[];
  assets: Asset[];
  findings: Finding[];
  scans: Scan[];
  events: Event[];
  audit: Event[];
  settings: Settings;
  dnsPosture?: DomainDNSPosture[];
  takeovers?: SubdomainTakeover[];
  hazards?: EndpointHazard[];
  webhooks?: NotificationWebhook[];
  runtime?: {
    liveScanning: boolean;
    workers: number;
    evidence: boolean;
    verificationRequired: boolean;
  };
};
export const relative = (date: string) => {
  if (!date) return "Never";
  const minutes = Math.max(
    0,
    Math.floor((Date.now() - new Date(date).getTime()) / 60000),
  );
  return minutes < 1
    ? "Just now"
    : minutes < 60
      ? `${minutes}m ago`
      : minutes < 1440
        ? `${Math.floor(minutes / 60)}h ago`
        : `${Math.floor(minutes / 1440)}d ago`;
};
export const dateTime = (date: string) =>
  date
    ? new Date(date).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "Never";
export async function api(path: string, method = "GET", data?: unknown) {
  const response = await fetch(`/api/${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: data ? JSON.stringify(data) : undefined,
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? "Something went wrong");
  return body;
}
export function exportCSV(name: string, rows: unknown[][]) {
  const csv = rows
    .map((row) =>
      row
        .map((value) => {
          let text = String(value ?? "");
          if (/^[=+@\-\t\r]/.test(text)) text = "'" + text;
          return `"${text.replaceAll('"', '""')}"`;
        })
        .join(","),
    )
    .join("\r\n");
  const blob = new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `surfacer-${name}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
