import type { QueryDocument, QueryFields } from "./query-language";
import type {
  Asset,
  Endpoint,
  Finding,
  Scan,
  Event,
  EndpointHazard,
  SubdomainTakeover,
} from "./types";

export const queryFields = {
  inventory: {
    host: "text",
    ip: "text",
    tech: "text",
    port: "number",
    status: "number",
    title: "text",
    severity: "text",
    findings: "number",
    exposure: "text",
    source: "text",
    blocked: "boolean",
    first_seen: "date",
    last_seen: "date",
  },
  findings: {
    title: "text",
    host: "text",
    severity: "text",
    status: "text",
    category: "text",
    security: "boolean",
    template: "text",
    cve: "text",
    cwe: "text",
    cvss: "number",
    component: "text",
    version: "text",
    port: "number",
    ip: "text",
    url: "text",
    tech: "text",
    parameter: "text",
    stage: "text",
    tool: "text",
    first_seen: "date",
    last_seen: "date",
  },
  endpoints: {
    url: "text",
    host: "text",
    method: "text",
    kind: "text",
    status: "number",
    parameter: "text",
    source: "text",
    first_seen: "date",
    last_seen: "date",
  },
  takeovers: {
    host: "text",
    cname: "text",
    provider: "text",
    status: "text",
    reopens: "number",
    first_seen: "date",
    last_seen: "date",
  },
  hazards: {
    url: "text",
    parameter: "text",
    class: "text",
    severity: "text",
    created: "date",
  },
  changes: {
    host: "text",
    field: "text",
    before: "text",
    after: "text",
    kind: "text",
    title: "text",
    detail: "text",
    actor: "text",
    at: "date",
  },
  scans: {
    domain: "text",
    status: "text",
    trigger: "text",
    assets: "number",
    findings: "number",
    worker: "text",
    error: "text",
    started: "date",
    finished: "date",
  },
} satisfies Record<string, QueryFields>;
export type QueryView = keyof typeof queryFields;
export const queryExamples: Record<QueryView, string[]> = {
  inventory: [
    "(port:443 OR port:8443) AND NOT tech:nginx",
    "exposure:exposed AND status>=400",
    "host:*.example.com AND findings>0",
  ],
  findings: [
    "status:open AND (severity:critical OR severity:high)",
    'security:true AND NOT status:"accepted risk"',
    "port:443 AND first_seen>=2026-01-01",
  ],
  endpoints: [
    "method:GET AND (status>=400 OR parameter:redirect)",
    "url:*/api/* AND NOT kind:static",
    "parameter:* AND status=200",
  ],
  takeovers: [
    "status:open AND (provider:github OR provider:amazon)",
    "reopens>0 AND NOT status:resolved",
  ],
  hazards: [
    "(class:ssrf_candidate OR class:redirect_candidate) AND severity:high",
    "parameter:url AND NOT url:*/test/*",
  ],
  changes: [
    "(kind:finding OR kind:resolved) AND NOT actor:system",
    "title:certificate",
  ],
  scans: [
    "status:partial OR status:failed",
    "findings>0 AND NOT status:running",
  ],
};
export function assetDocument(a: Asset, openFindings: number): QueryDocument {
  return {
    host: a.host,
    ip: a.ip,
    tech: a.technologies,
    port: a.ports,
    status: a.status || undefined,
    title: a.title,
    severity: a.severity,
    findings: openFindings,
    exposure: openFindings ? "exposed" : "clear",
    source: a.source,
    blocked: !!a.blocked,
    first_seen: a.firstSeen,
    last_seen: a.lastSeen,
  };
}
export function findingDocument(f: Finding, security: boolean): QueryDocument {
  return {
    title: f.title,
    host: f.host,
    severity: f.severity,
    status: f.status,
    category: f.category || "vulnerability",
    security,
    template: f.template,
    cve: f.cves,
    cwe: f.cwes,
    cvss: f.cvssScore,
    component: f.dependency?.name,
    version: f.dependency?.version,
    port: f.port,
    ip: f.ip,
    url: f.matchedAt,
    tech: f.technologies,
    parameter: f.parameters,
    stage: f.stageName,
    tool: f.tool,
    first_seen: f.firstSeen,
    last_seen: f.lastSeen,
  };
}
export function endpointDocument(
  e: Endpoint & { host: string },
): QueryDocument {
  return {
    url: e.url,
    host: e.host,
    method: e.method,
    kind: e.kind,
    status: e.status || undefined,
    parameter: e.parameters,
    source: e.source,
    first_seen: e.firstSeen,
    last_seen: e.lastSeen,
  };
}
export function takeoverDocument(t: SubdomainTakeover): QueryDocument {
  return {
    host: t.subdomain,
    cname: t.cname,
    provider: t.serviceProvider,
    status: t.status,
    reopens: t.reopenCount,
    first_seen: t.firstSeen,
    last_seen: t.lastSeen,
  };
}
export function hazardDocument(h: EndpointHazard): QueryDocument {
  return {
    url: h.url,
    parameter: h.parameter,
    class: h.hazardClass,
    severity: h.severity,
    created: h.createdAt,
  };
}
export function eventDocument(e: Event): QueryDocument {
  return { kind: e.kind, title: e.title, detail: e.detail, actor: e.actor, at: e.at, host: e.change?.host, field: e.change?.field, before: e.change?.before, after: e.change?.after };
}
export function scanDocument(s: Scan): QueryDocument {
  return {
    domain: s.domain,
    status: s.status,
    trigger: s.trigger,
    assets: s.assets,
    findings: s.findings,
    worker: s.worker,
    error: s.error,
    started: s.startedAt,
    finished: s.finishedAt,
  };
}
