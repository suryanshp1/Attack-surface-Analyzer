import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
const secret = () => randomBytes(32).toString("hex");
const defaults = {
  API_TOKEN: secret(),
  WORKSPACE_TOKEN: secret(),
  WORKER_TOKEN: secret(),
  EGRESS_SECRET: secret(),
  POSTGRES_PASSWORD: secret(),
  POSTGRES_APP_PASSWORD: secret(),
  S3_ACCESS_KEY: "surfacer",
  S3_SECRET_KEY: secret(),
  FRONTEND_PORT: "3000",
  REQUIRE_DNS_VERIFICATION: "false",
};
let content = existsSync(".env") ? readFileSync(".env", "utf8") : "";
const present = new Set(content.split("\n").map((line) => line.split("=")[0]));
for (const [key, value] of Object.entries(defaults))
  if (!present.has(key)) content += `${key}=${value}\n`;
writeFileSync(".env", content, { mode: 0o600 });
console.log(
  "Deployment credentials are ready in .env. Existing values were preserved. Use WORKSPACE_TOKEN from this file to sign in.",
);
