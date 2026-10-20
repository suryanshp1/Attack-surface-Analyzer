import test from "node:test";
import assert from "node:assert/strict";
import { hostInScope, urlInScope } from "../lib/domain-scope.ts";
import { parseWorkspaceRoute, workspaceHref } from "../lib/workspace-route.ts";

test("assessment scope uses hostname boundaries and normalizes DNS case", () => {
  for (const host of ["example.com", "api.example.com", "API.EXAMPLE.COM."]) assert.equal(hostInScope(host, "example.com"), true);
  for (const host of ["notexample.com", "example.com.evil.invalid", "example.net"]) assert.equal(hostInScope(host, "example.com"), false);
  assert.equal(urlInScope("https://api.example.com/path?url=evil.invalid", "example.com"), true);
  assert.equal(urlInScope("https://evil.invalid/example.com?domain=example.com", "example.com"), false);
  assert.equal(urlInScope("https://example.com@evil.invalid/path", "example.com"), false);
  assert.equal(urlInScope("not a URL", "all"), false);
});

test("assessment filters and selected DNS domain survive route round trips", () => {
  for (const hash of [
    "#hazards?hazardClass=ssrf_candidate&target=target-1&q=redirect",
    "#takeovers?takeoverStatus=suppressed&target=target-1&q=github",
    "#governance?dnsDomain=example.com&target=target-1",
  ]) {
    const route = parseWorkspaceRoute(hash);
    assert.deepEqual(parseWorkspaceRoute(workspaceHref(route)), route);
  }
});
