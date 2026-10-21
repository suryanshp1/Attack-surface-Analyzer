import test from "node:test";
import assert from "node:assert/strict";
import { compileQuery, builderFromQuery, builderToQuery, builderError, ruleOperators, newRule, newGroup } from "../lib/query-language.ts";
import {
  queryFields,
  queryExamples,
  assetDocument,
  endpointDocument,
  findingDocument,
  eventDocument,
} from "../lib/query-fields.ts";
import { parseWorkspaceRoute, workspaceHref } from "../lib/workspace-route.ts";

const fields = {
  host: "text",
  status: "number",
  tech: "text",
  blocked: "boolean",
  seen: "date",
};
const doc = {
  host: "api.example.com",
  status: 403,
  tech: ["Nginx", "Node.js"],
  blocked: false,
  seen: "2026-10-20T08:00:00Z",
};
const matches = (query, value = doc) => {
  const result = compileQuery(query, fields);
  assert.equal(result.error, null, query);
  return result.matches(value);
};
test("boolean precedence, implicit AND, grouping, and nested NOT", () => {
  assert.equal(matches("host:missing OR host:api AND status>=400"), true);
  assert.equal(matches("(host:missing OR host:api) AND status<400"), false);
  assert.equal(matches("NOT (status<400 OR blocked:true) tech:nginx"), true);
  assert.equal(matches("NOT NOT host:api"), true);
  assert.equal(matches("host:api and not tech:apache"), true);
});
test("contains, exact, arrays, wildcard anchoring, and missing values", () => {
  assert.equal(matches("tech:node"), true);
  assert.equal(matches("tech=node"), false);
  assert.equal(matches('tech="NODE.JS"'), true);
  assert.equal(matches("tech!=nginx"), false);
  assert.equal(matches("host:*.example.com"), true);
  assert.equal(matches("host:example*"), false);
  assert.equal(matches("host:*example*"), true);
  assert.equal(matches("tech:*"), true);
  assert.equal(matches("NOT tech:*", { tech: [] }), true);
  assert.equal(matches("tech!=nginx", {}), true);
  assert.equal(matches("status:*", { status: 0 }), true);
  assert.equal(matches("blocked:false"), true);
  assert.equal(matches("status>=400 status<500"), true);
  assert.equal(matches("seen>=2026-10-20 AND seen<2026-10-21"), true);
});
test("quoted phrases, punctuation, escaped quotes, and literal regex characters", () => {
  assert.equal(matches('"api.example.com"'), true);
  assert.equal(matches('host="a \\"quote\\""', { host: 'a "quote"' }), true);
  assert.equal(
    matches('host:"https://api.example.com/a?q=1"', {
      host: "https://api.example.com/a?q=1",
    }),
    true,
  );
  assert.equal(matches('host:"[a-z]+"', { host: "[a-z]+" }), true);
  assert.equal(matches('"OR"', { host: "or" }), true);
  assert.equal(matches(""), true);
});
test("invalid expressions return actionable errors and never match", () => {
  for (const query of [
    "host:",
    "host:api OR",
    "status>=*",
    "host==api",
    "AND host:api",
    "(host:api",
    "host:api)",
    "unknown:api",
    "status:abc",
    "blocked:yes",
    "host>3",
    "seen:garbage",
    'host:"unclosed',
    "host::api",
    "host:api AND OR tech:nginx",
    '"unterminated\\',
  ]) {
    const result = compileQuery(query, fields);
    assert.match(result.error, /column \d+/u, query);
    assert.equal(result.matches(doc), false, query);
  }
  for (const query of [
    "x".repeat(4097),
    "(".repeat(34) + "host:api" + ")".repeat(34),
    "NOT ".repeat(34) + "host:api",
    "x ".repeat(513),
  ]) {
    assert.ok(compileQuery(query, fields).error);
  }
});
test("all shipped examples compile against their view schema", () => {
  for (const [view, examples] of Object.entries(queryExamples)) {
    for (const example of examples)
      assert.equal(
        compileQuery(example, queryFields[view]).error,
        null,
        example,
      );
  }
});
test("record adapters preserve unobserved responses and finding categories", () => {
  const endpoint = {
    url: "https://example.com/a",
    host: "example.com",
    status: 0,
    parameters: [],
  };
  assert.equal(
    compileQuery("status:*", queryFields.endpoints).matches(
      endpointDocument(endpoint),
    ),
    false,
  );
  assert.equal(
    compileQuery(
      "category:vulnerability AND security:true",
      queryFields.findings,
    ).matches(findingDocument({ category: undefined }, true)),
    true,
  );
  const asset = {
    host: "example.com",
    technologies: ["nginx"],
    ports: [443],
    status: 0,
    findings: 99,
  };
  assert.equal(
    compileQuery(
      "port:443 AND findings=2 AND exposure:exposed AND NOT status:*",
      queryFields.inventory,
    ).matches(assetDocument(asset, 2)),
    true,
  );
});
test("legacy filter links become visible equivalent queries and survive canonical round trips", () => {
  const cases = [
    [
      "#inventory?tech=Nginx&port=443&exposure=exposed",
      'tech="Nginx" AND port="443" AND exposure="exposed"',
    ],
    [
      "#findings?findingStatus=accepted+risk&findingCategory=security&severity=high",
      'status="accepted risk" AND severity="high" AND security:true',
    ],
    ["#endpoints?kind=form&mode=historical", 'kind="form"'],
    ["#hazards?hazardClass=ssrf_candidate", 'class="ssrf_candidate"'],
    ["#takeovers?takeoverStatus=suppressed", 'status="suppressed"'],
    ["#scans?scanStatus=partial", 'status="partial"'],
    ["#changes?changeKind=finding", "(kind:finding OR kind:resolved)"],
  ];
  for (const [hash, query] of cases) {
    const route = parseWorkspaceRoute(hash);
    assert.equal(route.query, query);
    assert.deepEqual(parseWorkspaceRoute(workspaceHref(route)), route);
  }
  const route = parseWorkspaceRoute(
    "#findings?severity=high&q=host%3Aapi%20OR%20host%3Awww&target=t1&detail=finding%3Af1",
  );
  assert.equal(route.query, '(host:api OR host:www) AND severity="high"');
  assert.equal(route.scope, "t1");
  assert.equal(route.detail.id, "f1");
});

test("CVE, dependency, zero CVSS and structured change filters use recorded fields", () => {
  const finding = findingDocument({ template: "retire:jquery:fixture", cves: ["CVE-2020-11022"], cwes: ["CWE-79"], cvssScore: 0, dependency: { name: "jquery", version: "1.12.4", detection: "filecontent", database: "fixture" } }, true);
  for (const query of ["cve:CVE-2020-11022", "cwe:CWE-79", "cvss=0", "component:jquery version=1.12.4"]) {
    const parsed = compileQuery(query, queryFields.findings);
    assert.equal(parsed.error, null);
    assert.equal(parsed.matches(finding), true, query);
  }
  assert.equal(compileQuery("cvss:*", queryFields.findings).matches(findingDocument({}, true)), false);
  const event = eventDocument({ kind: "certificate", change: { host: "api.example.com", field: "certificateIssuer", before: ["Issuer A"], after: ["Issuer B"] } });
  const parsed = compileQuery('host:api.example.com AND field:certificateIssuer AND before:"Issuer A" AND after:"Issuer B"', queryFields.changes);
  assert.equal(parsed.error, null);
  assert.equal(parsed.matches(event), true);
});

test("visual builder round trips boolean groups, NOT, existence and all shipped examples", () => {
  const cases = [
    [fields, 'host:api OR status>=400 AND NOT blocked:true'],
    [fields, 'NOT (host:missing OR (status>=400 AND NOT tech:node))'],
    [fields, 'NOT NOT host:api'],
    [fields, 'status:* AND NOT tech:*'],
    [fields, '"api.example.com" AND NOT "missing"'],
    [fields, 'status!=403 OR seen>=2026-10-20'],
    ...Object.entries(queryExamples).flatMap(([view, examples]) => examples.map(example => [queryFields[view], example])),
  ];
  const documents = [doc, {}, { host: 'missing', status: 0, blocked: true, tech: ['node'], seen: '2026-10-21' }, { status: 'open', severity: 'critical', security: true, port: 443 }, { status: 'resolved', severity: 'high', security: false }, { host: 'api.example.com', port: [443, 8443], findings: 3 }];
  for (const [schema, query] of cases) {
    const builder = builderFromQuery(query, schema);
    assert.ok(builder, query);
    assert.equal(builderError(builder, schema), null, query);
    const original = compileQuery(query, schema);
    const serialized = compileQuery(builderToQuery(builder), schema);
    assert.equal(serialized.error, null, query);
    for (const record of documents) assert.equal(serialized.matches(record), original.matches(record), query);
  }
});

test("builder values cannot introduce query operators and preserve literal escapes", () => {
  for (const value of ['a" OR blocked:true OR host:"b', 'AND', 'https://example.com/a?x=1', String.raw`C:\files\app`, 'line one\nline two', 'a\tb', 'say "hello"']) {
    const group = { kind: 'group', combinator: 'AND', negate: false, children: [{ kind: 'rule', field: 'host', operator: '=', value, negate: false }] };
    const query = builderToQuery(group);
    const parsed = compileQuery(query, fields);
    assert.equal(parsed.error, null, query);
    assert.equal(parsed.matches({ host: value }), true, query);
    assert.equal(parsed.matches({ host: 'unrelated', blocked: true }), false, query);
    const restored = builderFromQuery(query, fields);
    assert.equal(restored.children[0].value, value);
  }
});

test("builder incomplete conditions cannot apply and typed operators respect field types", () => {
  assert.equal(builderError({ kind: 'group', combinator: 'AND', negate: false, children: [] }, fields), null);
  assert.match(builderError(newGroup(fields), fields), /Enter a value/);
  assert.match(builderError({ kind: 'group', combinator: 'AND', negate: false, children: [{ kind: 'group', combinator: 'OR', negate: false, children: [] }] }, fields), /empty group/);
  assert.equal(builderFromQuery('unknown:value', fields), null);
  const rule = newRule(fields);
  assert.equal(rule.field, 'host');
  assert.equal(ruleOperators('text').some(op => op.value === '>'), false);
  assert.equal(ruleOperators('boolean').some(op => op.value === ':'), false);
  assert.equal(ruleOperators('number').some(op => op.value === '>='), true);
  assert.equal(ruleOperators('date').find(op => op.value === '>=').label, 'On or after');
  assert.equal(builderError({ kind: 'rule', field: 'status', operator: '=', value: '0', negate: false }, fields), null);
  assert.equal(builderError({ kind: 'rule', field: 'blocked', operator: '=', value: 'false', negate: false }, fields), null);
  assert.match(builderError({ kind: 'rule', field: 'status', operator: '>=', value: 'abc', negate: false }, fields), /number/);
});
