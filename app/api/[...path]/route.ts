import { NextRequest } from "next/server";
import { timingSafeEqual } from "node:crypto";
export const dynamic = "force-dynamic";
function equal(a: string, b: string) {
  return (
    Buffer.byteLength(a) === Buffer.byteLength(b) &&
    timingSafeEqual(Buffer.from(a), Buffer.from(b))
  );
}
async function proxy(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  if (request.method !== "GET") {
    const origin = request.headers.get("origin");
    try {
      if (origin && new URL(origin).host !== request.headers.get("host"))
        return Response.json(
          { error: "Cross-origin writes are not allowed" },
          { status: 403 },
        );
    } catch {
      return Response.json({ error: "Invalid origin" }, { status: 403 });
    }
  }
  const workspaceToken = process.env.WORKSPACE_TOKEN;
  const session = request.cookies.get("surfacer_session")?.value ?? "";
  const bearer = request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
  const owner = workspaceToken && equal(session,workspaceToken);
  const userKey = /^surf_key_[a-f0-9]{64}$/.test(bearer) ? bearer : /^surf_key_[a-f0-9]{64}$/.test(session) ? session : "";
  if (workspaceToken && !owner && !userKey) return Response.json({error:"Sign in to your workspace",auth:true},{status:401});
  const headers: Record<string,string> = {"Content-Type":"application/json"};
  const apiToken=owner || !workspaceToken ? process.env.API_TOKEN : userKey;
  if(apiToken)headers.Authorization=`Bearer ${apiToken}`;
  let body: string | undefined;
  if (request.method !== "GET" && request.body) {
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 32768) {
        await reader.cancel();
        return Response.json(
          { error: "Request exceeds 32 KB" },
          { status: 413 },
        );
      }
      chunks.push(chunk.value);
    }
    body = Buffer.concat(chunks).toString("utf8");
  }
  try {
    const response = await fetch(
      `${process.env.API_URL ?? "http://127.0.0.1:8080"}/api/${path.map(encodeURIComponent).join("/")}`,
      {
        method: request.method,
        headers,
        body,
        cache: "no-store",
        signal: request.signal,
      },
    );
    return new Response(response.body, {
      status: response.status,
      headers: {
        "Content-Type":
          response.headers.get("Content-Type") ?? "application/json",
        "Cache-Control": "no-store",
        ...(response.headers.get("Content-Disposition") ? {"Content-Disposition":response.headers.get("Content-Disposition")!} : {}),
        "X-Accel-Buffering": "no",
      },
    });
  } catch {
    return Response.json(
      {
        error:
          "The Go API is unavailable. Start the full app with npm run dev.",
      },
      { status: 503 },
    );
  }
}
export { proxy as GET, proxy as POST, proxy as PATCH, proxy as DELETE };
