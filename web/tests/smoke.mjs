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
assert.ok(!/\\b(?:localStorage|sessionStorage)\\s*(?:\\.|\\[)/.test(js), "tokens must not be persisted in browser storage");
assert.ok(css.includes(".live-data-tables"), "live API table styling is missing");
assert.ok(js.includes('$("[data-action]")'), "all action controls must use the multi-element selector");
assert.ok(!js.includes('document.addEventListener("click",e=>{const button=e.target.closest("[data-feature-action]")'), "feature actions must not be registered twice");
console.log("Sentinel web smoke checks passed.");
