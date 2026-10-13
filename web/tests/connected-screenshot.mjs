import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";

const consoleUrl = process.env.SENTINEL_CONSOLE_URL;
const apiBase = process.env.SENTINEL_API_BASE;
const email = process.env.SENTINEL_DEMO_EMAIL;
const password = process.env.SENTINEL_DEMO_PASSWORD;
if (!consoleUrl || !apiBase || !email || !password) {
  throw new Error("Set SENTINEL_CONSOLE_URL, SENTINEL_API_BASE, SENTINEL_DEMO_EMAIL, and SENTINEL_DEMO_PASSWORD as protected GitHub Actions secrets.");
}
const parsedConsole = new URL(consoleUrl);
const parsedAPI = new URL(apiBase);
if (parsedConsole.protocol !== "https:" || parsedAPI.protocol !== "https:") {
  throw new Error("Connected screenshot workflow requires HTTPS console and API origins.");
}

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  await page.goto(parsedConsole.origin, { waitUntil: "networkidle" });
  await page.locator("#connectButton").click();
  const baseInput = page.locator("#apiBaseInput");
  const isReadOnly = await baseInput.evaluate(el => el.readOnly);
  if (isReadOnly) {
    const configured = await baseInput.inputValue();
    if (new URL(configured).origin !== parsedAPI.origin) {
      throw new Error("The deployed console is pinned to a different API origin than SENTINEL_API_BASE.");
    }
  } else {
    await baseInput.fill(parsedAPI.origin);
  }
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
