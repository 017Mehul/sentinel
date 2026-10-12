import { cp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const raw = process.env.SENTINEL_API_BASE;
if (!raw) {
  throw new Error("SENTINEL_API_BASE is required for a production static build; refusing to publish an unbound console.");
}

let parsed;
try {
  parsed = new URL(raw);
} catch {
  throw new Error("SENTINEL_API_BASE must be a valid HTTPS origin.");
}
if (
  parsed.protocol !== "https:" ||
  !parsed.hostname ||
  parsed.username ||
  parsed.password ||
  parsed.search ||
  parsed.hash ||
  (parsed.pathname !== "/" && parsed.pathname !== "")
) {
  throw new Error("SENTINEL_API_BASE must be an HTTPS origin without credentials, path, query, or fragment.");
}

const root = process.cwd();
const dist = path.join(root, "dist");
const assets = [
  "index.html",
  "app.js",
  "styles.css",
  "favicon.svg",
  "api-docs.html",
  "api-docs.js",
  "openapi.yaml",
];

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
for (const asset of assets) {
  await cp(path.join(root, asset), path.join(dist, asset));
}
await writeFile(
  path.join(dist, "config.js"),
  "window.SENTINEL_API_BASE = " + JSON.stringify(parsed.origin) + ";\n" +
    "window.SENTINEL_ALLOW_API_URL_OVERRIDE = false;\n",
  { mode: 0o644 },
);
console.log("Built Sentinel static console for the configured HTTPS API origin.");
