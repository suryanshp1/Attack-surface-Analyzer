"use client";

import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  ChevronRight,
  Clock3,
  Globe2,
  Network,
  Radar,
  Shield,
  TriangleAlert,
} from "lucide-react";
import {
  overviewMetrics,
  dailyActivity,
  findingAgeDays,
  issueAgeLabels,
  type IssueAge,
} from "@/lib/overview-metrics";
import { dateTime, relative, type Finding, type State } from "@/lib/types";
import {
  updateWorkspaceRoute,
  useWorkspaceFilter,
  openWorkspaceDetail,
  type Page,
} from "@/lib/workspace-route";

const ageGroups: IssueAge[] = ["recent", "month", "older", "unknown"];
const activityGroups = ["assets", "findings", "resolved", "other"] as const;
const activityLabels = {
  assets: "Asset discoveries",
  findings: "New findings",
  resolved: "Resolutions",
  other: "Other changes",
};
const countLabel = (count: number, singular: string, plural = `${singular}s`) =>
  `${count} ${count === 1 ? singular : plural}`;
const dayLabel = (date: string) =>
  new Date(`${date}T12:00:00Z`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });

export function OverviewDashboard({
  state,
  scope,
  events,
  go,
  selectFinding,
  run,
}: {
  state: State;
  scope: string;
  events: State["events"];
  go: (page: Page) => void;
  selectFinding: (id: string) => void;
  run: () => void;
}) {
  const [requestedDays, setDays] = useWorkspaceFilter("activityDays", "14");
  const days = requestedDays === "7" ? 7 : 14;
  const now = Date.now();
  const metrics = overviewMetrics(state, scope, now);
  const bins = dailyActivity(events, days, now);
  const activity = bins.reduce(
    (totals, bin) => ({
      assets: totals.assets + bin.assets,
      findings: totals.findings + bin.findings,
      resolved: totals.resolved + bin.resolved,
      other: totals.other + bin.other,
      total: totals.total + bin.total,
    }),
    { assets: 0, findings: 0, resolved: 0, other: 0, total: 0 },
  );
  const chartMax = Math.max(1, ...bins.map((bin) => bin.total));
  const chartTicks =
    chartMax === 1 ? [0, 1] : [0, Math.ceil(chartMax / 2), chartMax];
  const severityMax = Math.max(1, ...metrics.severity.map((row) => row.count));
  const lastObserved = [
    ...metrics.assets.map((asset) => asset.lastSeen),
    ...metrics.findings.map((finding) => finding.lastSeen),
  ]
    .filter(
      (stamp) => Number.isFinite(Date.parse(stamp)) && Date.parse(stamp) <= now,
    )
    .sort()
    .at(-1);
  const needsCoverage = metrics.unscanned + metrics.incomplete;
  const view = (page: Page, query = "", target = scope) =>
    updateWorkspaceRoute({
      page,
      scope: target,
      query,
      detail: null,
      filters: { p: "1" },
    });
  const issueQuery = "status:open AND security:true";
  const canRun =
    ["owner", "analyst"].includes(state.me?.role ?? "") &&
    !state.settings.paused &&
    metrics.ready > 0;
  const recentEvents = events
    .filter(
      (event) =>
        Number.isFinite(Date.parse(event.at)) && Date.parse(event.at) <= now,
    )
    .slice()
    .sort((a, b) => b.at.localeCompare(a.at))
    .slice(0, 4);
  const warning = !metrics.targets.length
    ? "Add a domain to establish your baseline."
    : metrics.high.length
      ? `${countLabel(metrics.high.length, "high or critical issue")} ${metrics.high.length === 1 ? "needs" : "need"} review.`
      : metrics.takeoverCandidates
        ? `${countLabel(metrics.takeoverCandidates, "open takeover candidate")} ${metrics.takeoverCandidates === 1 ? "needs" : "need"} review.`
        : needsCoverage
          ? `${countLabel(needsCoverage, "target")} ${needsCoverage === 1 ? "needs" : "need"} assessment follow-up.`
          : "Keep your assessment up to date.";
  return (
    <div className="overview-dashboard">
      <div className="overview-freshness">
        <span>
          <Clock3 size={14} /> Latest observation{" "}
          <strong title={lastObserved ? dateTime(lastObserved) : undefined}>
            {lastObserved ? relative(lastObserved) : "Not available"}
          </strong>
        </span>
        <span>
          Latest attempt{" "}
          <strong>
            {metrics.latest
              ? `${metrics.latest.status} · ${relative(metrics.latest.startedAt)}`
              : "No scans yet"}
          </strong>
        </span>
      </div>
      <div className="overview-kpis">
        <button className="overview-kpi" onClick={() => view("Inventory")}>
          <span>
            Discovered hosts <Network size={17} />
          </span>
          <strong>{metrics.assets.length.toLocaleString()}</strong>
          <small>
            {countLabel(metrics.newAssets, "new host")} first seen in 24h
          </small>
        </button>
        <button
          className="overview-kpi"
          onClick={() => view("Findings", issueQuery)}
        >
          <span>
            Open security issues <Shield size={17} />
          </span>
          <strong>
            {metrics.open.length.toLocaleString()}{" "}
            <em className="overview-critical-text">
              {metrics.high.length} high / critical
            </em>
          </strong>
          <small>
            Across {countLabel(metrics.affectedHosts, "host")} · excludes
            inventory observations
          </small>
        </button>
        <button
          className="overview-kpi"
          onClick={() =>
            view(
              "Findings",
              `${issueQuery} AND (severity:high OR severity:critical) AND first_seen<=${JSON.stringify(new Date(now - 30 * 86400000).toISOString())}`,
            )
          }
        >
          <span>
            High / critical aged 30+ days <Clock3 size={17} />
          </span>
          <strong>{metrics.overdueHigh.toLocaleString()}</strong>
          <small>Age since first seen · review remediation</small>
        </button>
        <button className="overview-kpi" onClick={() => go("Scan activity")}>
          <span>
            Latest runs completed <Radar size={17} />
          </span>
          <strong>
            {metrics.completed}
            <em> / {metrics.targets.length} targets</em>
          </strong>
          <small>
            {metrics.unscanned} unscanned · {metrics.incomplete} need follow-up
          </small>
        </button>
      </div>
      <section
        className="overview-next-action"
        aria-label="Recommended next action"
      >
        <TriangleAlert size={21} aria-hidden="true" />
        <div>
          <h2>{warning}</h2>
          <p>
            {!metrics.targets.length
              ? state.me?.role === "owner"
                ? "Add a root domain, then run an authorized scan."
                : "Ask a workspace owner to add a root domain, then an owner or analyst can run an assessment."
              : `${needsCoverage ? `${countLabel(needsCoverage, "target")} ${needsCoverage === 1 ? "has" : "have"} no scan or a latest attempt with unfinished work. ` : ""}${metrics.targets.length - metrics.ready} not scan-ready. A completed bounded scan does not establish a clean assessment.`}
          </p>
        </div>
        <button
          className="button"
          onClick={() =>
            !metrics.targets.length
              ? go("Targets")
              : metrics.high.length
                ? view(
                    "Findings",
                    `${issueQuery} AND (severity:high OR severity:critical)`,
                  )
                : metrics.takeoverCandidates
                  ? view("Takeovers", "status:open")
                  : go("Scan activity")
          }
        >
          {!metrics.targets.length
            ? state.me?.role === "owner"
              ? "Add target"
              : "View targets"
            : metrics.high.length
              ? "Review priority issues"
              : metrics.takeoverCandidates
                ? "Review takeover candidates"
                : "Review scans"}
          <ArrowRight size={15} />
        </button>
      </section>

      <nav
        className="overview-review-queues"
        aria-label="Additional review queues"
      >
        <button onClick={() => view("Takeovers", "status:open")}>
          <span>
            Open takeover candidates<small>Review provider evidence</small>
          </span>
          <strong>{metrics.takeoverCandidates ?? "Unavailable"}</strong>
          <ChevronRight size={14} />
        </button>
        <button onClick={() => go("Hazards")}>
          <span>
            Parameter hazard candidates
            <small>Heuristics, not confirmed vulnerabilities</small>
          </span>
          <strong>{metrics.hazardCandidates ?? "Unavailable"}</strong>
          <ChevronRight size={14} />
        </button>
        <button onClick={() => go("Governance")}>
          <span>
            Email policy reviews
            <small>Domains with missing / permissive policy</small>
          </span>
          <strong>{metrics.emailPolicyReviews ?? "Unavailable"}</strong>
          <ChevronRight size={14} />
        </button>
      </nav>

      <div className="overview-analysis-grid">
        <section
          className="overview-panel"
          aria-labelledby="overview-risk-heading"
        >
          <header>
            <div>
              <h2 id="overview-risk-heading">Open issues by severity & age</h2>
              <p>Current open security issues, aged from first observation.</p>
            </div>
            <button
              className="text-action"
              onClick={() => view("Findings", issueQuery)}
            >
              Review all <ArrowUpRight size={14} />
            </button>
          </header>
          <div className="overview-age-legend">
            {ageGroups.map((age) => (
              <span key={age}>
                <i className={`overview-age-${age}`} />
                {issueAgeLabels[age]}
              </span>
            ))}
          </div>
          <div className="overview-risk-chart">
            {metrics.severity.map((row) => (
              <button
                className="overview-risk-row"
                key={row.name}
                aria-label={`${row.name}: ${row.count} open issues. ${ageGroups.map((age) => `${issueAgeLabels[age]}: ${row.ages[age]}`).join(". ")}. View findings.`}
                onClick={() =>
                  view(
                    "Findings",
                    `${issueQuery} AND ${row.name === "other" ? "NOT (severity:critical OR severity:high OR severity:medium OR severity:low OR severity:info)" : `severity:${row.name}`}`,
                  )
                }
              >
                <span
                  className={`overview-severity overview-severity-${row.name}`}
                >
                  {row.name}
                </span>
                <span className="overview-risk-track" aria-hidden="true">
                  <span
                    className="overview-risk-total"
                    style={{ width: `${(row.count / severityMax) * 100}%` }}
                  >
                    {ageGroups.map((age) => (
                      <span
                        key={age}
                        className={`overview-age-${age}`}
                        title={`${issueAgeLabels[age]}: ${row.ages[age]}`}
                        style={{
                          width: `${row.count ? (row.ages[age] / row.count) * 100 : 0}%`,
                        }}
                      />
                    ))}
                  </span>
                </span>
                <strong>{row.count}</strong>
                <ChevronRight size={13} />
              </button>
            ))}
          </div>
          {!metrics.open.length && (
            <p className="overview-empty">
              No open security issues recorded. Review assessment gaps before
              drawing conclusions.
            </p>
          )}
          <details className="overview-chart-data">
            <summary>View issue age counts</summary>
            <div className="overview-data-scroll">
              <table>
                <caption>
                  Open security issues by severity and observed age
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    {ageGroups.map((age) => (
                      <th scope="col" key={age}>
                        {issueAgeLabels[age]}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {metrics.severity.map((row) => (
                    <tr key={row.name}>
                      <th scope="row">{row.name}</th>
                      {ageGroups.map((age) => (
                        <td key={age}>{row.ages[age]}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
          <div className="overview-panel-note">
            {
              metrics.findings.filter(
                (finding) =>
                  finding.status === "resolved" &&
                  (!finding.category ||
                    ["vulnerability", "secret"].includes(finding.category)),
              ).length
            }{" "}
            resolved ·{" "}
            {
              metrics.findings.filter(
                (finding) =>
                  ["accepted risk", "false positive"].includes(
                    finding.status,
                  ) &&
                  (!finding.category ||
                    ["vulnerability", "secret"].includes(finding.category)),
              ).length
            }{" "}
            accepted risk / false positive. These are current states, not a
            remediation trend.
          </div>
        </section>
        <section
          className="overview-panel"
          aria-labelledby="overview-activity-heading"
        >
          <header>
            <div>
              <h2 id="overview-activity-heading">Recorded surface changes</h2>
              <p>
                {dayLabel(bins[0].date)} – {dayLabel(bins.at(-1)!.date)} · daily
                counts in UTC
              </p>
            </div>
            <select
              aria-label="Activity chart period"
              value={days}
              onChange={(event) => setDays(event.target.value)}
            >
              <option value={7}>7 days</option>
              <option value={14}>14 days</option>
            </select>
          </header>
          <div className="overview-activity-summary">
            <strong>{activity.total}</strong>
            <span>
              recorded changes{" "}
              <small>
                {activity.findings} new finding events · {activity.resolved}{" "}
                resolution events
              </small>
            </span>
          </div>
          <svg
            className="overview-activity-chart"
            viewBox="0 0 520 166"
            role="img"
            aria-label={`${activity.total} recorded changes over ${days} days. ${activity.assets} asset discoveries, ${activity.findings} new findings, ${activity.resolved} resolutions, ${activity.other} other changes. Daily data follows in View daily counts.`}
          >
            {chartTicks.map((value) => (
              <g key={value}>
                <line
                  x1="28"
                  x2="510"
                  y1={128 - (value / chartMax) * 104}
                  y2={128 - (value / chartMax) * 104}
                  className="overview-chart-grid"
                />
                <text
                  x="22"
                  y={132 - (value / chartMax) * 104}
                  textAnchor="end"
                >
                  {value}
                </text>
              </g>
            ))}
            {bins.map((bin, index) => {
              const band = 470 / days,
                x = 34 + index * band,
                width = band * 0.62;
              let accumulated = 0;
              return (
                <g key={bin.date}>
                  <title>
                    {dayLabel(bin.date)} UTC: {bin.total} changes.{" "}
                    {activityGroups
                      .map((group) => `${activityLabels[group]}: ${bin[group]}`)
                      .join(". ")}
                  </title>
                  {activityGroups.map((group) => {
                    const height = (bin[group] / chartMax) * 104;
                    accumulated += height;
                    return (
                      <rect
                        key={group}
                        x={x}
                        y={128 - accumulated}
                        width={width}
                        height={height}
                        className={`overview-activity-${group}`}
                        rx="1"
                      />
                    );
                  })}
                  {(index === 0 ||
                    index === days - 1 ||
                    index === Math.floor(days / 2)) && (
                    <text
                      x={x + width / 2}
                      y="151"
                      textAnchor={
                        index === 0
                          ? "start"
                          : index === days - 1
                            ? "end"
                            : "middle"
                      }
                    >
                      {dayLabel(bin.date)}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
          <div className="overview-age-legend overview-event-legend">
            {activityGroups.map((group) => (
              <span key={group}>
                <i className={`overview-activity-${group}`} />
                {activityLabels[group]}
              </span>
            ))}
          </div>
          <details className="overview-chart-data">
            <summary>View daily counts</summary>
            <div className="overview-data-scroll">
              <table>
                <caption>Recorded changes by UTC date</caption>
                <thead>
                  <tr>
                    <th scope="col">Date</th>
                    {activityGroups.map((group) => (
                      <th scope="col" key={group}>
                        {activityLabels[group]}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {bins.map((bin) => (
                    <tr key={bin.date}>
                      <th scope="row">{bin.date}</th>
                      {activityGroups.map((group) => (
                        <td key={group}>{bin[group]}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
          <div className="overview-panel-note">
            Retained event log only. A zero means no recorded events for that
            day; it does not establish an unchanged or clean surface.
          </div>
        </section>
      </div>

      <section
        className="overview-panel overview-targets"
        aria-labelledby="overview-targets-heading"
      >
        <header>
          <div>
            <h2 id="overview-targets-heading">Assessment by target</h2>
            <p>
              All domains in scope, including targets that cannot currently
              scan. Sorted by high / critical issues.
            </p>
          </div>
          <button className="text-action" onClick={() => go("Targets")}>
            Manage targets <ArrowUpRight size={14} />
          </button>
        </header>
        {!metrics.targetRows.length ? (
          <div className="overview-empty">
            <strong>No targets in this scope.</strong>
            <p>Add a domain to start collecting observations.</p>
            <button className="button" onClick={() => go("Targets")}>
              Manage targets <ArrowRight size={14} />
            </button>
          </div>
        ) : (
          <div
            className="overview-target-scroll"
            tabIndex={0}
            role="region"
            aria-label="Assessment table; scroll horizontally to compare checks"
          >
            <table className="overview-target-table">
              <caption className="sr-only">
                Latest scan status, readiness and observed counts by target
              </caption>
              <thead>
                <tr>
                  <th scope="col">Domain / readiness</th>
                  <th scope="col">Hosts / services</th>
                  <th scope="col">Open security issues</th>
                  <th scope="col">Latest attempt</th>
                  <th scope="col">HTTP / detection checks</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {metrics.targetRows.map((row) => (
                  <tr key={row.target.id}>
                    <th scope="row">
                      <button
                        className="overview-domain-link"
                        onClick={() => view("Inventory", "", row.target.id)}
                      >
                        {row.target.domain}
                        <ArrowUpRight size={13} />
                      </button>
                      <small>
                        {row.target.canScan
                          ? "Ready to scan"
                          : `Not scan-ready · ${row.target.status}`}
                      </small>
                    </th>
                    <td>
                      <strong>{row.hosts}</strong> hosts
                      <small>{row.services} service URLs</small>
                    </td>
                    <td>
                      <button
                        className="overview-issue-link"
                        onClick={() =>
                          view("Findings", issueQuery, row.target.id)
                        }
                      >
                        {row.issues} open{" "}
                        <span
                          className={row.urgent ? "overview-critical-text" : ""}
                        >
                          {row.urgent} high / critical
                        </span>
                      </button>
                    </td>
                    <td>
                      <span
                        className={`overview-assessment-state ${row.assessment === "Completed" ? "overview-state-completed" : ""}`}
                      >
                        {row.assessment}
                      </span>
                      <small>
                        {row.latest
                          ? relative(row.latest.startedAt)
                          : "No attempt recorded"}
                      </small>
                      {row.successful &&
                        row.successful.id !== row.latest?.id && (
                          <small>
                            Last completed{" "}
                            {relative(
                              row.successful.finishedAt ||
                                row.successful.startedAt,
                            )}
                          </small>
                        )}
                    </td>
                    <td>
                      <CoverageCount
                        label="HTTP"
                        value={row.latest?.coverage?.http}
                      />
                      <CoverageCount
                        label="Detection"
                        value={row.latest?.coverage?.detection}
                      />
                    </td>
                    <td>
                      <button
                        className="overview-row-action"
                        aria-label={`Review ${row.target.domain} ${row.latest ? "scan" : "target"}`}
                        onClick={() =>
                          row.latest
                            ? openWorkspaceDetail("scan", row.latest.id)
                            : openWorkspaceDetail("target", row.target.id)
                        }
                      >
                        Review
                        <ChevronRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="overview-panel-note">
          HTTP counts service origins; detection counts required
          service/template pairs. Counts describe the latest bounded attempt.
          Unavailable counters and unscanned targets are not zero coverage gaps.
        </div>
      </section>

      <div className="overview-analysis-grid overview-bottom-grid">
        <section
          className="overview-panel"
          aria-labelledby="overview-priority-heading"
        >
          <header>
            <div>
              <h2 id="overview-priority-heading">Review these issues first</h2>
              <p>Severity first, then oldest first-seen observation.</p>
            </div>
            <button
              className="text-action"
              onClick={() => view("Findings", issueQuery)}
            >
              All open issues <ArrowUpRight size={14} />
            </button>
          </header>
          <div className="overview-priority-list">
            {metrics.priority.slice(0, 4).map((finding) => (
              <PriorityIssue
                key={finding.id}
                finding={finding}
                now={now}
                select={selectFinding}
              />
            ))}
            {!metrics.open.length && (
              <div className="overview-empty">
                <strong>
                  {needsCoverage
                    ? "Assessment follow-up is still needed."
                    : "No open security issues recorded."}
                </strong>
                <p>
                  {metrics.targets.length
                    ? "Check scan coverage and observation freshness."
                    : "Start with a domain you are authorized to assess."}
                </p>
                <button className="button" disabled={!canRun} onClick={run}>
                  {state.settings.paused ? "Scanning paused" : "Run a scan"}
                  <Radar size={14} />
                </button>
                {!canRun && (
                  <p>
                    {state.me?.role === "viewer"
                      ? "Ask an owner or analyst to run an assessment."
                      : !metrics.ready
                        ? "Manage targets to review scan readiness."
                        : "Resume scanning in Settings to continue."}
                  </p>
                )}
              </div>
            )}
          </div>
        </section>
        <section
          className="overview-panel"
          aria-labelledby="overview-service-heading"
        >
          <header>
            <div>
              <h2 id="overview-service-heading">Observed web responses</h2>
              <p>
                {metrics.services.total} unique service URLs on discovered
                hosts.
              </p>
            </div>
            <Globe2 size={18} />
          </header>
          <div className="overview-response-list">
            {metrics.services.responses.map((response) => (
              <div key={response.id}>
                <span>{response.label}</span>
                <meter
                  min={0}
                  max={Math.max(1, metrics.services.total)}
                  value={response.count}
                  aria-label={response.label}
                >
                  {response.count}
                </meter>
                <strong>{response.count}</strong>
              </div>
            ))}
          </div>
          <div className="overview-panel-note">
            {!metrics.services.total
              ? "No service URLs have been observed. "
              : ""}
            HTTP errors and missing responses do not establish vulnerability or
            absence. Services may have different observation times.
            <button className="text-action" onClick={() => go("Inventory")}>
              Inspect inventory <ArrowRight size={14} />
            </button>
          </div>
        </section>
      </div>
      <section
        className="overview-recent-events"
        aria-labelledby="overview-events-heading"
      >
        <header>
          <div>
            <h2 id="overview-events-heading">Latest recorded changes</h2>
            <p>Recent activity in the selected domain scope.</p>
          </div>
          <button className="text-action" onClick={() => go("Changes")}>
            View event log <ArrowUpRight size={14} />
          </button>
        </header>
        <div>
          {recentEvents.map((event) => (
            <button key={event.id} onClick={() => go("Changes")}>
              <Activity size={16} />
              <span>
                <strong>{event.title}</strong>
                <small>{event.detail}</small>
              </span>
              <time dateTime={event.at} title={dateTime(event.at)}>
                {relative(event.at)}
              </time>
              <ChevronRight size={14} />
            </button>
          ))}
          {!recentEvents.length && (
            <p className="overview-empty">
              No retained change events in this scope. Events appear when scans
              record changes.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
function CoverageCount({
  label,
  value,
}: {
  label: string;
  value: { finished: number; remaining: number } | undefined;
}) {
  return (
    <small className="overview-coverage-count">
      <span>{label}</span>
      {value
        ? value.finished + value.remaining === 0
          ? "No eligible checks"
          : `${value.finished} finished · ${value.remaining} unfinished`
        : "Unavailable"}
    </small>
  );
}
function PriorityIssue({
  finding,
  now,
  select,
}: {
  finding: Finding;
  now: number;
  select: (id: string) => void;
}) {
  const age = findingAgeDays(finding.firstSeen, now);
  return (
    <button
      className="overview-priority-issue"
      onClick={() => select(finding.id)}
    >
      <span
        className={`overview-severity overview-severity-${finding.severity}`}
      >
        {finding.severity}
      </span>
      <span>
        <strong>{finding.title}</strong>
        <small>{finding.host}</small>
      </span>
      <span className="overview-issue-age">
        {age === null ? "Age unavailable" : `${age}d since first seen`}
      </span>
      <ChevronRight size={14} />
    </button>
  );
}
