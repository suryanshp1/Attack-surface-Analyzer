import { createHash, randomBytes } from "node:crypto";

export const sessionMaxAgeSeconds = 8 * 60 * 60;
const idleMilliseconds = 30 * 60 * 1000;
const maximumSessions = 1000;
type BrowserSession = {
  credential: string;
  expiresAt: number;
  lastSeen: number;
  controller: AbortController;
};

// The supported topology has one web process. Keep this shared across route
// bundles; a process restart deliberately signs every browser out.
const scope = globalThis as typeof globalThis & {
  surfacerBrowserSessions?: Map<string, BrowserSession>;
};
const sessions = scope.surfacerBrowserSessions ??= new Map<string, BrowserSession>();
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const expired = (session: BrowserSession, now: number) =>
  now >= session.expiresAt || now - session.lastSeen >= idleMilliseconds;

export function revokeBrowserSession(value: string) {
  const key = digest(value);
  sessions.get(key)?.controller.abort();
  sessions.delete(key);
}

export function createBrowserSession(credential: string): string | undefined {
  const now = Date.now();
  for (const [key, session] of sessions) {
    if (expired(session, now)) {
      session.controller.abort();
      sessions.delete(key);
    }
  }
  if (sessions.size >= maximumSessions) return undefined;
  const value = randomBytes(32).toString("base64url");
  sessions.set(digest(value), {
    credential,
    expiresAt: now + sessionMaxAgeSeconds * 1000,
    lastSeen: now,
    controller: new AbortController(),
  });
  return value;
}

export function resolveBrowserSession(value: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) return undefined;
  const session = sessions.get(digest(value));
  if (!session) return undefined;
  const now = Date.now();
  if (expired(session, now)) {
    revokeBrowserSession(value);
    return undefined;
  }
  session.lastSeen = now;
  return {
    credential: session.credential,
    // A stream cannot outlive the session, even if no further requests arrive.
    signal: AbortSignal.any([
      session.controller.signal,
      AbortSignal.timeout(Math.min(session.expiresAt - now, idleMilliseconds)),
    ]),
  };
}
