import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";

const apiBase = process.env.SENTINEL_API_BASE;
const email = process.env.SENTINEL_DEMO_EMAIL;
const password = process.env.SENTINEL_DEMO_PASSWORD;
if (!apiBase || !email || !password) {
  throw new Error("Set SENTINEL_API_BASE, SENTINEL_DEMO_EMAIL, and SENTINEL_DEMO_PASSWORD as protected GitHub Actions secrets.");
}

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  await page.goto("http://127.0.0.1:5173", { waitUntil: "networkidle" });
  await page.locator("#connectButton").click();
  await page.locator("#apiBaseInput").fill(apiBase);
  await page.locator("#apiEmail").fill(email);
  await page.locator("#apiPassword").fill(password);
  await page.locator("#connectSubmit").click();
  await page.waitForFunction(() => {
    const pill = document.querySelector(".demo-pill");
    return Boolean(pill && pill.classList.contains("live-pill") && pill.textContent.includes("Live API connected"));
  }, { timeout: 45000 });
  await mkdir("artifacts", { recursive: true });
  await page.screenshot({ path: "artifacts/sentinel-connected.png", fullPage: true });
  console.log("Connected console screenshot captured after successful API login.");
} finally {
  await browser.close();
}
