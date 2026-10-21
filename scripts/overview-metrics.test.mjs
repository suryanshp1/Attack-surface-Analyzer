import test from "node:test";
import assert from "node:assert/strict";
import {
  overviewMetrics,
  findingAgeDays,
  issueAge,
  dailyActivity,
  assessmentState,
  serviceObservations,
  eventMatchesDomain,
} from "../lib/overview-metrics.ts";
import { compileQuery } from "../lib/query-language.ts";
import { queryFields, findingDocument } from "../lib/query-fields.ts";
const now = Date.parse("2026-10-21T12:00:00Z");
const ago = (days) => new Date(now - days * 86400000).toISOString();
const target = (id, domain, canScan = true) => ({
  id,
  domain,
  canScan,
  status: canScan ? "ready" : "paused",
});
const asset = (id, targetId, extra = {}) => ({
  id,
  targetId,
  host: `${id}.example.com`,
  firstSeen: ago(2),
  lastSeen: ago(1),
  technologies: [],
  ports: [],
  status: 0,
  ...extra,
});
const finding = (id, extra = {}) => ({
  id,
  host: "api.example.com",
  status: "open",
  severity: "high",
  firstSeen: ago(40),
  lastSeen: ago(1),
  ...extra,
});
const scan = (id, targetId, status = "completed", extra = {}) => ({
  id,
  targetId,
  status,
  startedAt: ago(1),
  finishedAt: ago(1),
  stages: [{ name: "Detection", status: "completed" }],
  ...extra,
});
const state = (extra) => ({
  targets: [target("t1", "example.com")],
  assets: [],
  findings: [],
  scans: [],
  events: [],
  ...extra,
});

test("overview counts open security issues without mixing candidate and inventory observations", () => {
  const data = state({
    findings: [
      finding("f1"),
      finding("f2", { severity: "critical", category: "secret" }),
      finding("f3", { status: "resolved" }),
      finding("f4", { category: "port" }),
      finding("f5", { category: "hazard" }),
      finding("f6", { status: "accepted risk" }),
      finding("f7", { host: "API.EXAMPLE.COM." }),
    ],
  });
  const result = overviewMetrics(data, "all", now);
  assert.equal(result.open.length, 3);
  assert.equal(result.high.length, 3);
  assert.equal(result.overdueHigh, 3);
  assert.equal(result.affectedHosts, 1);
  assert.equal(
    result.severity.reduce((n, row) => n + row.count, 0),
    3,
  );
});
test("age buckets use exact boundaries and keep invalid/future timestamps unknown", () => {
  for (const [days, bucket] of [
    [0, "recent"],
    [6.999, "recent"],
    [7, "month"],
    [29.999, "month"],
    [30, "older"],
  ])
    assert.equal(issueAge(ago(days), now), bucket);
  for (const stamp of ["", "not-a-date", ago(-1)]) {
    assert.equal(findingAgeDays(stamp, now), null);
    assert.equal(issueAge(stamp, now), "unknown");
  }
});
test("severity totals retain informational and unrecognized values; priority sorts oldest within severity", () => {
  const result = overviewMetrics(
    state({
      findings: [
        finding("new-high", { firstSeen: ago(1) }),
        finding("old-high"),
        finding("info", { severity: "info" }),
        finding("unknown", { severity: "custom", firstSeen: "" }),
        finding("critical", { severity: "critical", firstSeen: ago(1) }),
      ],
    }),
    "all",
    now,
  );
  assert.deepEqual(
    result.priority.map((f) => f.id),
    ["critical", "old-high", "new-high", "info", "unknown"],
  );
  assert.equal(
    result.severity.find((row) => row.name === "other").ages.unknown,
    1,
  );
});
test("selected target scope uses hostname boundaries and keeps non-ready, unscanned domains visible", () => {
  const data = state({
    targets: [target("t1", "example.com", false), target("t2", "other.com")],
    assets: [
      asset("api", "t1"),
      asset("gone", "t1", { removed: true }),
      asset("other", "t2"),
    ],
    findings: [
      finding("in"),
      finding("lookalike", { host: "notexample.com" }),
      finding("evil", { host: "example.com.evil.test" }),
      finding("other", { host: "other.com" }),
    ],
    scans: [scan("s2", "t2")],
  });
  const result = overviewMetrics(data, "t1", now);
  assert.equal(result.assets.length, 1);
  assert.deepEqual(
    result.open.map((f) => f.id),
    ["in"],
  );
  assert.equal(result.ready, 0);
  assert.equal(result.unscanned, 1);
  assert.equal(result.targetRows.length, 1);
  assert.equal(result.latest, undefined);
});
test("latest assessment state cannot be replaced by a previous completed run", () => {
  const result = overviewMetrics(
    state({
      scans: [
        scan("old", "t1", "completed", { startedAt: ago(10) }),
        scan("new", "t1", "partial"),
      ],
    }),
    "all",
    now,
  );
  assert.equal(result.completed, 0);
  assert.equal(result.incomplete, 1);
  assert.equal(result.targetRows[0].assessment, "Partial");
  assert.equal(result.targetRows[0].successful.id, "old");
  assert.equal(assessmentState(scan("active", "t1", "running")), "In progress");
  assert.equal(
    assessmentState(
      scan("gap", "t1", "completed", {
        coverage: { http: { finished: 1, remaining: 1 } },
      }),
    ),
    "Coverage gaps",
  );
  assert.equal(
    assessmentState(
      scan("stage-gap", "t1", "completed", {
        stages: [
          {
            name: "Detection",
            status: "completed",
            coverageStatus: "incomplete",
          },
        ],
      }),
    ),
    "Coverage gaps",
  );
  const legacy = overviewMetrics(
    state({ scans: [scan("legacy", "t1")] }),
    "all",
    now,
  );
  assert.equal(legacy.targetRows[0].latest.coverage, undefined);
});
test("service response distribution includes every observed service and deduplicates URLs", () => {
  const result = serviceObservations([
    asset("a", "t1", {
      services: [
        { url: "https://a", status: 200 },
        { url: "https://b", status: 302 },
        { url: "https://c", status: 403 },
        { url: "https://d", status: 503 },
        { url: "https://e", status: 0 },
      ],
    }),
    asset("b", "t1", { url: "https://a", status: 200 }),
    asset("c", "t1", { url: "https://f", status: 0 }),
  ]);
  assert.equal(result.total, 6);
  assert.deepEqual(
    result.responses.map((row) => row.count),
    [1, 1, 1, 1, 2],
  );
  assert.equal(
    serviceObservations([asset("no-url", "t1", { status: 200 })]).total,
    0,
  );
});
test("activity bins use UTC dates, include today, and exclude future, old, and invalid events", () => {
  const event = (at, kind) => ({ at, kind });
  const bins = dailyActivity(
    [
      event("2026-10-20T23:30:00-02:00", "finding"),
      event("2026-10-20T23:00:00Z", "resolved"),
      event(ago(13.5), "asset"),
      event(ago(15), "asset"),
      event(ago(-1), "finding"),
      event("invalid", "finding"),
      event(ago(1), "port"),
    ],
    14,
    now,
  );
  assert.equal(bins.length, 14);
  assert.equal(bins[0].date, "2026-10-08");
  assert.equal(bins.at(-1).findings, 1);
  assert.equal(bins.at(-2).resolved, 1);
  assert.equal(bins.at(-2).other, 1);
  assert.equal(
    bins.reduce((n, b) => n + b.total, 0),
    4,
  );
});
test("event domain attribution rejects lookalike suffixes and labels only explicit hostname references", () => {
  for (const detail of [
    "API.EXAMPLE.COM. · port 443",
    "Finding on https://app.example.com/path",
    "example.com",
  ])
    assert.equal(eventMatchesDomain({ detail }, "example.com"), true);
  for (const detail of [
    "notexample.com",
    "example.com.evil.test",
    "a-example.com",
    "no domain attribution",
  ])
    assert.equal(eventMatchesDomain({ detail }, "example.com"), false);
});
test("specialist review queues remain separate and distinguish missing datasets from empty results", () => {
  const data = state({
    takeovers: [
      { status: "open", subdomain: "app.example.com" },
      { status: "resolved", subdomain: "old.example.com" },
      { status: "open", subdomain: "outside.com" },
    ],
    hazards: [
      { url: "https://example.com/a" },
      { url: "invalid" },
      { url: "https://outside.com" },
    ],
    dnsPosture: [
      { domain: "example.com", spfStatus: "missing", dmarcPolicy: "reject" },
      { domain: "EXAMPLE.COM.", spfStatus: "permissive", dmarcPolicy: "none" },
      { domain: "outside.com", spfStatus: "permissive", dmarcPolicy: "none" },
    ],
  });
  const result = overviewMetrics(data, "t1", now);
  assert.equal(result.takeoverCandidates, 1);
  assert.equal(result.hazardCandidates, 1);
  assert.equal(result.emailPolicyReviews, 1);
  assert.equal(result.open.length, 0);
  assert.equal(overviewMetrics(state({}), "all", now).takeoverCandidates, null);
  assert.equal(
    overviewMetrics(state({ takeovers: [] }), "all", now).takeoverCandidates,
    0,
  );
});
test("30-day issue drilldown query agrees with the displayed age count", () => {
  const findings = [
    finding("old"),
    finding("boundary", { firstSeen: ago(30) }),
    finding("recent", { firstSeen: ago(29.9) }),
    finding("missing", { firstSeen: "" }),
  ];
  const query = `status:open AND security:true AND (severity:high OR severity:critical) AND first_seen<=${JSON.stringify(ago(30))}`;
  const compiled = compileQuery(query, queryFields.findings);
  assert.equal(compiled.error, null);
  assert.equal(
    findings.filter((f) => compiled.matches(findingDocument(f, true))).length,
    overviewMetrics(state({ findings }), "all", now).overdueHigh,
  );
});
