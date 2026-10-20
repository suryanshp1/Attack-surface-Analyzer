import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
const { NextRequest } = require("next/server");
const owner = "synthetic-workspace-owner";
const member = `surf_key_${"a".repeat(64)}`;

// Execute the actual route handlers with a mocked upstream. Each fixture has an
// isolated process-global session store and clock; no network or real secrets.
function fixture() {
  let now = 1_800_000_000_000;
  const calls = [];
  const env = { WORKSPACE_TOKEN: owner, API_TOKEN: "synthetic-api-service", API_URL: "http://api.invalid" };
  const context = vm.createContext({
    Buffer, Response, AbortSignal, AbortController, URL, console,
    Date: class extends Date { static now() { return now; } },
    process: { env },
    fetch: async (url, options) => {
      calls.push({ url, options });
      return Response.json({ ok: true });
    },
  });
  const cache = new Map();
  function load(path) {
    const absolute = resolve(path);
    if (cache.has(absolute)) return cache.get(absolute).exports;
    const module = { exports: {} };
    cache.set(absolute, module);
    const code = ts.transpileModule(readFileSync(absolute, "utf8"), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    }).outputText;
    const localRequire = (id) => id.startsWith(".")
      ? load(resolve(dirname(absolute), `${id}.ts`))
      : require(id);
    vm.runInContext(`(function(exports, require, module) { ${code}\n})`, context)(module.exports, localRequire, module);
    return module.exports;
  }
  const session = load("app/api/session/route.ts");
  const proxy = load("app/api/[...path]/route.ts");
  const store = load("lib/browser-session.ts");
  function request(path, method = "GET", { cookie, token, body, origin } = {}) {
    return new NextRequest(`https://workspace.test${path}`, {
      method,
      headers: {
        host: "workspace.test",
        ...(cookie ? { cookie: `surfacer_session=${cookie}` } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(origin ? { origin } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  }
  async function login(token = owner, cookie) {
    const response = await session.POST(request("/api/session", "POST", { body: { token }, cookie }));
    assert.equal(response.status, 200);
    return { cookie: response.cookies.get("surfacer_session").value, response };
  }
  const forward = (path, options = {}) => {
    const method = options.method ?? "GET";
    const req = request(`/api/${path}`, method, options);
    return proxy[method](req, { params: Promise.resolve({ path: path.split("?")[0].split("/") }) });
  };
  return { session, store, calls, env, context, request, login, forward, advance: (ms) => { now += ms; } };
}

test("browser cookies use opaque IDs; legacy credential cookies are rejected", async () => {
  const f = fixture();
  const { cookie, response } = await f.login();
  assert.match(cookie, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(cookie, owner);
  assert.match(response.headers.get("set-cookie"), /HttpOnly/i);
  assert.match(response.headers.get("set-cookie"), /Secure/i);
  assert.match(response.headers.get("set-cookie"), /SameSite=Strict/i);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal((await f.forward("me", { cookie })).status, 200);
  assert.equal(f.calls.at(-1).options.headers.Authorization, "Bearer synthetic-api-service");
  assert.equal((await f.forward("me", { cookie: owner })).status, 401);
  assert.equal((await f.forward("me", { cookie: member })).status, 401);
  assert.equal((await f.forward("me", { cookie: `${cookie.slice(0, -1)}!` })).status, 401);
});

test("logout invalidates copied cookies and aborts active stream requests", async () => {
  const f = fixture();
  const { cookie } = await f.login();
  await f.forward("events", { cookie });
  const streamSignal = f.calls.at(-1).options.signal;
  assert.equal(streamSignal.aborted, false);
  const logout = await f.session.DELETE(f.request("/api/session", "DELETE", { cookie }));
  assert.equal(logout.status, 200);
  assert.equal(streamSignal.aborted, true);
  assert.equal((await f.forward("me", { cookie })).status, 401);
});

test("idle and absolute session expiry are enforced server side", async () => {
  const f = fixture();
  const idle = await f.login();
  f.advance(30 * 60 * 1000);
  assert.equal((await f.forward("me", { cookie: idle.cookie })).status, 401);
  const active = await f.login();
  for (let i = 0; i < 23; i++) {
    f.advance(20 * 60 * 1000);
    assert.equal((await f.forward("me", { cookie: active.cookie })).status, 200);
  }
  f.advance(20 * 60 * 1000);
  assert.equal((await f.forward("me", { cookie: active.cookie })).status, 401);
});

test("session replacement and workspace credential rotation invalidate old access", async () => {
  const f = fixture();
  const first = await f.login();
  const second = await f.login(owner, first.cookie);
  assert.notEqual(first.cookie, second.cookie);
  assert.equal((await f.forward("me", { cookie: first.cookie })).status, 401);
  f.env.WORKSPACE_TOKEN = "rotated-owner";
  assert.equal((await f.forward("me", { cookie: second.cookie })).status, 401);
});

test("member sessions preserve backend revocation checks and direct bearer clients", async () => {
  const f = fixture();
  const { cookie } = await f.login(member);
  assert.equal((await f.forward("me", { cookie })).status, 200);
  assert.equal(f.calls.at(-1).options.headers.Authorization, `Bearer ${member}`);
  assert.equal((await f.forward("me", { token: member })).status, 200);
  f.context.fetch = async () => Response.json({ error: "revoked" }, { status: 401 });
  assert.equal((await f.forward("me", { cookie })).status, 401);
  assert.equal((await f.session.POST(f.request("/api/session", "POST", { body: { token: member } }))).status, 401);
});

test("cross-origin and malformed-origin requests cannot log out a session", async () => {
  const f = fixture();
  const { cookie } = await f.login();
  for (const origin of ["https://evil.test", "not a URL"]) {
    assert.equal((await f.session.DELETE(f.request("/api/session", "DELETE", { cookie, origin }))).status, 403);
    assert.equal((await f.session.POST(f.request("/api/session", "POST", { body: { token: owner }, origin }))).status, 403);
  }
  assert.equal((await f.forward("me", { cookie })).status, 200);
});

test("proxy preserves deletion IDs, report filters, and repeated encoded query values", async () => {
  const f = fixture();
  await f.forward("webhooks?id=synthetic-hook", { method: "DELETE", token: member });
  assert.equal(f.calls.at(-1).url, "http://api.invalid/api/webhooks?id=synthetic-hook");
  const query = "targetId=target-1&severity=high&status=accepted+risk&tag=a%26b&tag=c";
  await f.forward(`reports.pdf?${query}`, { token: member });
  assert.equal(f.calls.at(-1).url, `http://api.invalid/api/reports.pdf?${query}`);
});

test("browser session capacity is bounded without evicting active sessions", () => {
  const f = fixture();
  const first = f.store.createBrowserSession(owner);
  for (let i = 1; i < 1000; i++) assert.ok(f.store.createBrowserSession(owner));
  assert.equal(f.store.createBrowserSession(owner), undefined);
  assert.ok(f.store.resolveBrowserSession(first));
  f.advance(30 * 60 * 1000);
  assert.ok(f.store.createBrowserSession(owner));
  assert.equal(f.store.resolveBrowserSession(first), undefined);
});
