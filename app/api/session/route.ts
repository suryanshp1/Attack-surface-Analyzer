import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "node:crypto";
import {
  createBrowserSession,
  revokeBrowserSession,
  sessionMaxAgeSeconds,
} from "../../../lib/browser-session";

function same(a: string, b: string) {
  return Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function validOrigin(request: NextRequest) {
  const origin = request.headers.get("origin");
  try {
    return !origin || new URL(origin).host === request.headers.get("host");
  } catch {
    return false;
  }
}

export async function POST(request: NextRequest) {
  if (!validOrigin(request)) return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
  let token: unknown;
  try {
    const reader = request.body?.getReader();
    if (!reader) throw Error();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        bytes += part.value.byteLength;
        if (bytes > 2048) {
          await reader.cancel().catch(() => undefined);
          return NextResponse.json({ error: "Request too large" }, { status: 413 });
        }
        chunks.push(part.value);
      }
    } finally {
      reader.releaseLock();
    }
    token = JSON.parse(Buffer.concat(chunks).toString("utf8")).token;
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
  if (typeof token !== "string" || token.length > 128) {
    return NextResponse.json({ error: "Invalid access token" }, { status: 401 });
  }
  const bootstrap = process.env.WORKSPACE_TOKEN;
  const owner = bootstrap && same(token, bootstrap);
  if (!owner) {
    if (!/^surf_key_[a-f0-9]{64}$/.test(token)) {
      return NextResponse.json({ error: "Invalid access token" }, { status: 401 });
    }
    try {
      const check = await fetch(`${process.env.API_URL ?? "http://127.0.0.1:8080"}/api/me`, {
        headers: { Authorization: `Bearer ${token}` },
        cache: "no-store",
        signal: AbortSignal.timeout(5000),
      });
      await check.body?.cancel();
      if (!check.ok) return NextResponse.json({ error: "Access key is invalid, expired or revoked" }, { status: 401 });
    } catch {
      return NextResponse.json({ error: "Authentication service unavailable" }, { status: 503 });
    }
  }
  revokeBrowserSession(request.cookies.get("surfacer_session")?.value ?? "");
  const session = createBrowserSession(token);
  if (!session) return NextResponse.json({ error: "Browser session limit reached" }, { status: 503 });
  const response = NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  response.cookies.set("surfacer_session", session, {
    httpOnly: true,
    sameSite: "strict",
    secure: request.nextUrl.protocol === "https:",
    path: "/",
    maxAge: sessionMaxAgeSeconds,
  });
  return response;
}

export async function DELETE(request: NextRequest) {
  if (!validOrigin(request)) return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
  revokeBrowserSession(request.cookies.get("surfacer_session")?.value ?? "");
  const response = NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
  response.cookies.set("surfacer_session", "", {
    httpOnly: true,
    sameSite: "strict",
    secure: request.nextUrl.protocol === "https:",
    path: "/",
    maxAge: 0,
  });
  return response;
}
