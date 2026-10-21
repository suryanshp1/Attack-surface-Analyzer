import type { Asset, Event, Finding, Scan, State } from "./types";

const day = 86_400_000;
export const overviewSeverities = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "other",
] as const;
export type IssueAge = "recent" | "month" | "older" | "unknown";
export const issueAgeLabels: Record<IssueAge, string> = {
  recent: "Under 7 days",
  month: "7–29 days",
  older: "30+ days",
  unknown: "Age unavailable",
};
export function isSecurityFinding(finding: Finding) {
  return (
    !finding.category || ["vulnerability", "secret"].includes(finding.category)
  );
}
export function findingAgeDays(firstSeen: string, now: number): number | null {
  const timestamp = Date.parse(firstSeen);
  return Number.isFinite(timestamp) && timestamp <= now
    ? Math.floor((now - timestamp) / day)
    : null;
}
export function issueAge(firstSeen: string, now: number): IssueAge {
  const age = findingAgeDays(firstSeen, now);
  return age === null
    ? "unknown"
    : age < 7
      ? "recent"
      : age < 30
        ? "month"
        : "older";
}
export function issueSeverity(
  finding: Finding,
): (typeof overviewSeverities)[number] {
  return (
    overviewSeverities.find((name) => name === finding.severity) ?? "other"
  );
}
export function eventMatchesDomain(event: Event, domain: string) {
  const root = domain.toLowerCase().replace(/\.$/, "");
  const names = event.detail.toLowerCase().split(/[^a-z0-9.-]+/);
  return names.some((name) => {
    const host = name.replace(/^\.+|\.+$/g, "");
    return host === root || host.endsWith(`.${root}`);
  });
}
export function assessmentState(scan?: Scan) {
  if (!scan) return "Unscanned";
  if (["queued", "running", "retrying"].includes(scan.status))
    return "In progress";
  if (scan.status === "completed") {
    const coverage = scan.coverage;
    const gaps =
      scan.stages.some(
        (stage) =>
          stage.coverageStatus === "incomplete" || stage.status !== "completed",
      ) ||
      (coverage?.http?.remaining ?? 0) > 0 ||
      (coverage?.detection?.remaining ?? 0) > 0 ||
      (coverage?.crawlRemaining ?? 0) > 0 ||
      (coverage?.portRemaining ?? 0) > 0 ||
      (coverage?.serviceIssueCount ?? 0) > 0;
    return gaps ? "Coverage gaps" : "Completed";
  }
  return (
    (
      { partial: "Partial", failed: "Failed", canceled: "Canceled" } as Record<
        string,
        string
      >
    )[scan.status] ?? "Unknown"
  );
}
export function dailyActivity(events: Event[], days: number, now: number) {
  const today = new Date(now);
  const midnight = Date.UTC(
    today.getUTCFullYear(),
    today.getUTCMonth(),
    today.getUTCDate(),
  );
  const bins = Array.from({ length: days }, (_, index) => ({
    date: new Date(midnight - (days - 1 - index) * day)
      .toISOString()
      .slice(0, 10),
    assets: 0,
    findings: 0,
    resolved: 0,
    other: 0,
    total: 0,
  }));
  const byDate = new Map(bins.map((bin) => [bin.date, bin]));
  for (const event of events) {
    const timestamp = Date.parse(event.at);
    if (!Number.isFinite(timestamp) || timestamp > now) continue;
    const bin = byDate.get(new Date(timestamp).toISOString().slice(0, 10));
    if (!bin) continue;
    const group =
      event.kind === "asset"
        ? "assets"
        : event.kind === "finding"
          ? "findings"
          : event.kind === "resolved"
            ? "resolved"
            : "other";
    bin[group]++;
    bin.total++;
  }
  return bins;
}
export function serviceObservations(assets: Asset[]) {
  // A persisted URL is an observation even when its probe did not receive a response.
  const observations = assets.flatMap((asset) => {
    const source = asset.services?.length
      ? asset.services
      : asset.url
        ? [{ url: asset.url, status: asset.status }]
        : [];
    return source;
  });
  const services = [
    ...new Map(
      observations
        .filter((service) => service.url)
        .map((service) => [service.url, service]),
    ).values(),
  ];
  const responses = [
    { id: "success", label: "2xx responses", count: 0 },
    { id: "redirect", label: "3xx redirects", count: 0 },
    { id: "client", label: "4xx responses", count: 0 },
    { id: "server", label: "5xx responses", count: 0 },
    { id: "unknown", label: "No classified response", count: 0 },
  ];
  for (const service of services) {
    const group =
      service.status >= 200 && service.status < 300
        ? 0
        : service.status >= 300 && service.status < 400
          ? 1
          : service.status >= 400 && service.status < 500
            ? 2
            : service.status >= 500 && service.status < 600
              ? 3
              : 4;
    responses[group].count++;
  }
  return { total: services.length, responses };
}
export function overviewMetrics(state: State, scope: string, now: number) {
  const targets = state.targets.filter(
    (target) => scope === "all" || target.id === scope,
  );
  const selectedIDs = new Set(targets.map((target) => target.id));
  const assets = state.assets.filter(
    (asset) =>
      !asset.removed && (scope === "all" || selectedIDs.has(asset.targetId)),
  );
  const within = (host: string, domain: string) => {
    const normalized = host.toLowerCase().replace(/\.$/, "");
    const root = domain.toLowerCase().replace(/\.$/, "");
    return normalized === root || normalized.endsWith(`.${root}`);
  };
  const findings = state.findings.filter(
    (finding) =>
      scope === "all" ||
      targets.some((target) => within(finding.host, target.domain)),
  );
  const open = findings.filter(
    (finding) => finding.status === "open" && isSecurityFinding(finding),
  );
  const high = open.filter((finding) =>
    ["critical", "high"].includes(finding.severity),
  );
  const severity = overviewSeverities.map((name) => {
    const issues = open.filter((finding) => issueSeverity(finding) === name);
    const ages = { recent: 0, month: 0, older: 0, unknown: 0 };
    for (const finding of issues) ages[issueAge(finding.firstSeen, now)]++;
    return { name, count: issues.length, ages };
  });
  const orderedScans = state.scans
    .filter((scan) => scope === "all" || selectedIDs.has(scan.targetId))
    .slice()
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  const targetRows = targets
    .map((target) => {
      const hosts = assets.filter((asset) => asset.targetId === target.id);
      const issues = open.filter((finding) =>
        within(finding.host, target.domain),
      );
      const latest = orderedScans.find((scan) => scan.targetId === target.id);
      const successful = orderedScans.find(
        (scan) =>
          scan.targetId === target.id && assessmentState(scan) === "Completed",
      );
      return {
        target,
        hosts: hosts.length,
        services: serviceObservations(hosts).total,
        issues: issues.length,
        urgent: issues.filter((finding) =>
          ["critical", "high"].includes(finding.severity),
        ).length,
        latest,
        successful,
        assessment: assessmentState(latest),
      };
    })
    .sort(
      (a, b) =>
        b.urgent - a.urgent ||
        b.issues - a.issues ||
        a.target.domain.localeCompare(b.target.domain),
    );
  const priority = open.slice().sort((a, b) => {
    const severity =
      overviewSeverities.indexOf(issueSeverity(a)) -
      overviewSeverities.indexOf(issueSeverity(b));
    return (
      severity ||
      (findingAgeDays(b.firstSeen, now) ?? -1) -
        (findingAgeDays(a.firstSeen, now) ?? -1) ||
      a.id.localeCompare(b.id)
    );
  });
  const overdueHigh = high.filter(
    (finding) => (findingAgeDays(finding.firstSeen, now) ?? -1) >= 30,
  ).length;
  const withinScope = (host: string) =>
    scope === "all" || targets.some((target) => within(host, target.domain));
  const takeoverCandidates = state.takeovers
    ? state.takeovers.filter(
        (candidate) =>
          candidate.status === "open" && withinScope(candidate.subdomain),
      ).length
    : null;
  const hazardCandidates = state.hazards
    ? state.hazards.filter((candidate) => {
        try {
          return withinScope(new URL(candidate.url).hostname);
        } catch {
          return false;
        }
      }).length
    : null;
  const emailPolicyReviews = state.dnsPosture
    ? new Set(
        state.dnsPosture
          .filter(
            (posture) =>
              withinScope(posture.domain) &&
              (["missing", "permissive"].includes(posture.spfStatus) ||
                ["missing", "none"].includes(posture.dmarcPolicy)),
          )
          .map((posture) => posture.domain.toLowerCase().replace(/\.$/, "")),
      ).size
    : null;
  return {
    targets,
    takeoverCandidates,
    hazardCandidates,
    emailPolicyReviews,
    assets,
    findings,
    open,
    high,
    severity,
    targetRows,
    priority,
    overdueHigh,
    affectedHosts: new Set(
      open.map((finding) => finding.host.toLowerCase().replace(/\.$/, "")),
    ).size,
    ready: targets.filter((target) => target.canScan).length,
    completed: targetRows.filter((row) => row.assessment === "Completed")
      .length,
    unscanned: targetRows.filter((row) => row.assessment === "Unscanned")
      .length,
    incomplete: targetRows.filter(
      (row) => !["Completed", "Unscanned"].includes(row.assessment),
    ).length,
    latest: orderedScans[0],
    services: serviceObservations(assets),
    newAssets: assets.filter((asset) => {
      const age = findingAgeDays(asset.firstSeen, now);
      return age !== null && age < 1;
    }).length,
  };
}
