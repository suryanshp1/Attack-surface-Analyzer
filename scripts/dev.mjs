import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";

// Launch the compiled API directly so Ctrl-C reaches it, including graceful shutdown.
const tempRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
const binary = join(
  tempRoot,
  `surfacer-api-${process.pid}${process.platform === "win32" ? ".exe" : ""}`,
);
const environment = {
  ...process.env,
  GOMODCACHE: process.env.GOMODCACHE ?? join(tempRoot, "surfacer-go-mod"),
  GOCACHE: process.env.GOCACHE ?? join(tempRoot, "surfacer-go-build"),
};
let api,
  web,
  stopping = false;
const build = spawn("go", ["build", "-o", binary, "."], {
  cwd: "backend",
  stdio: "inherit",
  env: environment,
});
function stop() {
  if (stopping) return;
  stopping = true;
  build.kill("SIGTERM");
  api?.kill("SIGTERM");
  web?.kill("SIGTERM");
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
process.on("exit", () => {
  try {
    rmSync(binary, { force: true });
  } catch {}
});
build.on("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
build.on("exit", (code) => {
  if (stopping) return;
  if (code !== 0) {
    process.exitCode = code ?? 1;
    return;
  }
  api = spawn(binary, [], {
    cwd: "backend",
    stdio: "inherit",
    env: environment,
  });
  web = spawn("npm", ["run", "dev:web"], {
    stdio: "inherit",
    env: process.env,
  });
  api.on("exit", (code) => {
    if (!stopping) {
      stop();
      process.exitCode = code ?? 0;
    }
  });
  web.on("exit", (code) => {
    stop();
    process.exitCode = code ?? 0;
  });
  api.on("error", (error) => {
    console.error(error.message);
    stop();
    process.exitCode = 1;
  });
  web.on("error", (error) => {
    console.error(error.message);
    stop();
    process.exitCode = 1;
  });
});
