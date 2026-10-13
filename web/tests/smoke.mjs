import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
const js = await readFile(new URL("../app.js", import.meta.url), "utf8");
const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");

for (const id of ["pageTitle", "pageSubtitle", "toast", "globalSearch", "activityChart", "usersTable", "overviewAuditTable", "connectButton"]) {
  // connectButton is injected at runtime; every other ID must exist in static markup or app source.
  assert.ok(html.includes(`id="${id}"`) || js.includes(`id="${id}"`), `missing expected UI target: ${id}`);
}
assert.ok(js.includes('request("/api/v1/users/me")'), "profile API is not wired");
assert.ok(js.includes('request("/api/v1/admin/users?page=1&page_size=100")'), "admin user directory is not wired");
assert.ok(js.includes('request("/api/v1/mfa/status")'), "MFA status API is not wired");
assert.ok(js.includes('request("/healthz")') && js.includes('request("/ready")'), "liveness/readiness probes are not wired");
assert.ok(js.includes('X-CSRF-Token'), "production refresh CSRF header is not wired");
assert.ok(!js.includes('localStorage') && !js.includes('sessionStorage'), "tokens must not be persisted in browser storage");
assert.ok(css.includes(".live-data-tables"), "live API table styling is missing");
console.log("Sentinel web smoke checks passed.");
