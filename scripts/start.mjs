import { cpSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";
const host = process.env.SURFACER_HOST ?? "127.0.0.1";
if (
  host !== "127.0.0.1" &&
  host !== "localhost" &&
  !process.env.WORKSPACE_TOKEN
)
  throw new Error(
    "Set WORKSPACE_TOKEN before exposing the frontend outside loopback.",
  );
if (!existsSync(".next/standalone/server.js"))
  throw new Error("Run npm run build first.");
cpSync(".next/static", ".next/standalone/.next/static", { recursive: true });
if (existsSync("public"))
  cpSync("public", ".next/standalone/public", { recursive: true });
const server = spawn(process.execPath, [".next/standalone/server.js"], {
  stdio: "inherit",
  env: { ...process.env, HOSTNAME: host },
});
process.on("SIGINT", () => server.kill("SIGINT"));
process.on("SIGTERM", () => server.kill("SIGTERM"));
server.on("exit", (code) => {
  process.exitCode = code ?? 0;
});
