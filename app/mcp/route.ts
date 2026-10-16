import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

// AI clients use individual member keys; browser cookies and service tokens
// never grant authority on this endpoint.
async function proxy(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (origin && origin !== request.nextUrl.origin) {
    return Response.json({ error: "Cross-origin requests are not allowed" }, { status: 403 });
  }
  const authorization = request.headers.get("authorization") ?? "";
  if (!/^Bearer surf_key_[a-f0-9]{64}$/.test(authorization)) {
    return Response.json({ error: "An active member access key is required" }, {
      status: 401,
      headers: { "WWW-Authenticate": 'Bearer realm="Surfacer MCP"', "Cache-Control": "no-store" },
    });
  }
  const headers = new Headers({ authorization });
  for (const name of ["accept", "content-type", "mcp-protocol-version", "mcp-session-id"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  let body: Uint8Array | undefined;
  if (request.body) {
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 32768) {
        await reader.cancel();
        return Response.json({ error: "Request exceeds 32 KB" }, { status: 413 });
      }
      chunks.push(chunk.value);
    }
    body = Buffer.concat(chunks);
  }
  try {
    const response = await fetch(`${process.env.API_URL ?? "http://127.0.0.1:8080"}/api/mcp`, {
      method: request.method,
      headers,
      body: body as BodyInit | undefined,
      cache: "no-store",
      signal: request.signal,
    });
    const returned = new Headers({ "Cache-Control": "no-store", "X-Accel-Buffering": "no" });
    for (const name of ["content-type", "allow", "www-authenticate", "mcp-session-id", "mcp-protocol-version", "x-request-id"]) {
      const value = response.headers.get(name);
      if (value) returned.set(name, value);
    }
    return new Response(response.body, { status: response.status, headers: returned });
  } catch {
    return Response.json({ error: "The Surfacer API is unavailable" }, { status: 503 });
  }
}

export { proxy as POST, proxy as GET, proxy as DELETE };
