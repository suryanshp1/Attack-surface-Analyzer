import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

// Exercise the actual route without starting Next or contacting a real API.
const source = await readFile(new URL("../app/mcp/route.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const route = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);
const key = `surf_key_${"a".repeat(64)}`;
function request(method = "POST", headers = {}, body) {
  const value = new Request("http://localhost:3000/mcp", { method, headers, body });
  value.nextUrl = new URL(value.url);
  return value;
}

test("MCP proxy requires member Bearer keys and never substitutes browser credentials", async () => {
  for (const headers of [{}, { cookie: "surfacer_session=bootstrap" }, { authorization: "Bearer service-token" }]) {
    const response = await route.POST(request("POST", headers));
    assert.equal(response.status, 401);
    assert.match(response.headers.get("www-authenticate"), /Bearer/);
  }
});

test("MCP proxy validates Origin even for reads", async () => {
  const response = await route.GET(request("GET", {
    authorization: `Bearer ${key}`, origin: "https://evil.example",
  }));
  assert.equal(response.status, 403);
});

test("MCP proxy bounds bodies before forwarding", async () => {
  const response = await route.POST(request("POST", { authorization: `Bearer ${key}` }, " ".repeat(32769)));
  assert.equal(response.status, 413);
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("MCP proxy handles interrupted uploads without forwarding partial requests", async () => {
  const originalFetch = globalThis.fetch;
  let forwarded = false;
  const body = new ReadableStream({
    start(controller) { controller.error(new Error("fixture interrupted upload")); },
  });
  try {
    globalThis.fetch = async () => { forwarded = true; throw new Error("must not forward"); };
    const value = request("POST", { authorization: `Bearer ${key}` });
    Object.defineProperty(value, "body", { value: body });
    const response = await route.POST(value);
    assert.equal(response.status, 400);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(forwarded, false);
    assert.equal(body.locked, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("MCP proxy rejects oversized uploads even if stream cancellation fails", async () => {
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(32769)); },
    cancel() { throw new Error("fixture failed cancellation"); },
  });
  const value = request("POST", { authorization: `Bearer ${key}` });
  Object.defineProperty(value, "body", { value: body });
  const response = await route.POST(value);
  assert.equal(response.status, 413);
  assert.equal(body.locked, false);
});

test("MCP proxy preserves protocol headers, caller identity, body, and upstream errors", async () => {
  const originalFetch = globalThis.fetch;
  const previousURL = process.env.API_URL;
  process.env.API_URL = "http://api-fixture:8080";
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, "http://api-fixture:8080/api/mcp");
      assert.equal(options.headers.get("authorization"), `Bearer ${key}`);
      assert.equal(options.headers.get("mcp-protocol-version"), "2025-11-25");
      assert.equal(options.headers.get("accept"), "application/json, text/event-stream");
      assert.equal(options.headers.get("cookie"), null);
      assert.equal(Buffer.from(options.body).toString(), '{"jsonrpc":"2.0"}');
      return new Response('{"error":"revoked"}', {
        status: 401, headers: { "content-type": "application/json", "www-authenticate": "Bearer", "x-request-id": "fixture" },
      });
    };
    const response = await route.POST(request("POST", {
      authorization: `Bearer ${key}`, cookie: "surfacer_session=bootstrap",
      origin: "http://localhost:3000", accept: "application/json, text/event-stream",
      "mcp-protocol-version": "2025-11-25",
    }, '{"jsonrpc":"2.0"}'));
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("www-authenticate"), "Bearer");
    assert.equal(response.headers.get("x-request-id"), "fixture");
    assert.equal(await response.text(), '{"error":"revoked"}');
  } finally {
    globalThis.fetch = originalFetch;
    if (previousURL === undefined) delete process.env.API_URL;
    else process.env.API_URL = previousURL;
  }
});

test("MCP proxy reports unavailable backend", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error("fixture unavailable"); };
    const response = await route.POST(request("POST", { authorization: `Bearer ${key}` }, "{}"));
    assert.equal(response.status, 503);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
