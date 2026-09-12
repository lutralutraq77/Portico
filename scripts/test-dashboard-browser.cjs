"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const readline = require("node:readline");
const { chromium } = require("playwright");
const lines = readline.createInterface({ input: process.stdin });
const iterator = lines[Symbol.asyncIterator]();

(async () => {
  const config = JSON.parse((await iterator.next()).value);
  await fs.mkdir(config.Report, { recursive: true });
  const browser = await chromium.launch({ executablePath: config.Browser, headless: true, args: ["--disable-background-networking"] });
  const checks = [];
  function checked(name) { checks.push(name); process.stdout.write(`BROWSER_CHECK ${name}\n`); }
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1050 }, colorScheme: "light", serviceWorkers: "block",
      proxy: { server: config.Proxy },
      clientCertificates: [{ origin: config.Origin, cert: Buffer.from(config.Certificate), key: Buffer.from(config.Key) }]
    });
    const page = await context.newPage();
    const scriptErrors = [], requests = [];
    page.on("pageerror", (error) => scriptErrors.push(error.message));
    page.on("request", (request) => requests.push(request.url()));
    const ready = async () => {
      await page.waitForFunction(() => document.querySelector(".inventory")?.getAttribute("aria-busy") === "false");
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false");
    };
    const response = await page.goto(`${config.Origin}/admin`, { waitUntil: "domcontentloaded" });
    assert.equal(response.status(), 200);
    assert.match(response.headers()["content-security-policy"], /default-src 'none'/);
    await ready();
    assert.equal(await page.locator("tbody tr").count(), 50);
    assert.equal(await page.locator("#next").isEnabled(), true);
    const firstPage = await page.locator("tbody").innerText();
    checked("authenticated real TLS inventory, bounded first page and CSP");

    await page.locator("#next").click(); await ready();
    assert.equal(await page.locator("tbody tr").count(), 5);
    assert.equal(await page.locator("#next").isDisabled(), true);
    const secondPage = await page.locator("tbody").innerText();
    await page.locator("#previous").click(); await ready();
    assert.equal(await page.locator("tbody").innerText(), firstPage);
    checked("forward and backward revision-bound pagination");
    assert.match(firstPage + secondPage, /<img src=x onerror=/);
    assert.equal(await page.locator("#records img").count(), 0);
    assert.equal(await page.evaluate(() => globalThis.metadataExecuted), undefined);
    checked("hostile metadata rendered as text without execution");

    await page.keyboard.press("Control+Home");
    await page.locator(".skip-link").focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.evaluate(() => document.activeElement.id), "content");
    await page.locator('nav a[data-section="resources"]').focus();
    await page.keyboard.press("Enter"); await ready();
    assert.equal(await page.locator("h1").innerText(), "Resources");
    assert.equal(await page.locator('nav a[aria-current="page"]').getAttribute("data-section"), "resources");
    checked("keyboard navigation and skip link");
    await page.screenshot({ path: path.join(config.Report, "desktop-resources.png"), fullPage: true });

    for (const section of ["devices", "connectors", "enrollments", "certificates", "users"]) {
      await page.locator(`nav a[data-section="${section}"]`).click(); await ready();
      assert.equal((await page.locator("h1").innerText()).toLowerCase(), section);
      assert.equal(await page.locator("table caption").count(), 1);
      assert.equal(await page.locator("thead th[scope=col]").count() > 0, true);
    }
    checked("all six sections and accessible table headings");
    await page.setViewportSize({ width: 360, height: 800 });
    await page.locator('nav a[data-section="resources"]').click(); await ready();
    const mobile = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth > innerWidth,
      navigation: [...document.querySelectorAll("nav a")].map((link) => { const rect = link.getBoundingClientRect(); return { width: rect.width, height: rect.height }; })
    }));
    assert.equal(mobile.overflow, false);
    assert.equal(mobile.navigation.every((rect) => rect.height >= 48 && rect.width >= 48), true);
    assert.equal((await page.locator("caption").boundingBox()).width > 250, true);
    await page.screenshot({ path: path.join(config.Report, "mobile-resources.png"), fullPage: true });
    await page.emulateMedia({ colorScheme: "dark" });
    await page.screenshot({ path: path.join(config.Report, "mobile-dark.png"), fullPage: true });
    checked("360px mobile reflow, 48px navigation targets and dark scheme");

    assert.deepEqual(await context.cookies(), []);
    assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
    assert.equal(requests.every((url) => new URL(url).origin === config.Origin), true);
    assert.deepEqual(scriptErrors, []);
    checked("no cookies, persistent browser storage, third-party requests or script errors");

    const endpoint = `${config.Origin}/api/v1/admin/dashboard/inventory`;
    await page.route(endpoint, (route) => route.abort("failed"));
    await page.locator("#refresh").click();
    await page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true");
    assert.equal(await page.locator("#records").innerText(), "");
    assert.equal(await page.locator("#next").isDisabled(), true);
    await page.unroute(endpoint);
    await page.locator("#refresh").click(); await ready();
    assert.equal(await page.locator("tbody tr").count() > 0, true);
    checked("network failure clears records and refresh recovers");

    process.stdout.write("PORTICO_BROWSER_REVOKE\n");
    assert.equal((await iterator.next()).value, "revoked");
    await page.locator("#refresh").click();
    await page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true");
    assert.equal(await page.locator("#records").innerText(), "");
    const denied = await page.evaluate(async () => { const r = await fetch("/admin.js", { cache: "no-store" }); return { status: r.status, body: await r.text() }; });
    assert.deepEqual(denied, { status: 403, body: '{"error":"request rejected"}' });
    await page.screenshot({ path: path.join(config.Report, "revoked.png"), fullPage: true });
    checked("live administrator revocation clears inventory and denies private assets");
    await context.close();
    await fs.writeFile(path.join(config.Report, "result.json"), JSON.stringify({ browser: browser.version(), playwright: require("playwright/package.json").version, checks, limitations: ["Ephemeral software identity; no physical security-key or platform custody qualification.", "Browser automation presents the client identity through Playwright's TLS proxy; upstream TLS validates the isolated root via process-only NODE_EXTRA_CA_CERTS."] }, null, 2) + "\n");
  } finally { await browser.close(); lines.close(); process.stdin.destroy(); }
  process.stdout.write("PORTICO_DASHBOARD_BROWSER_PASS\n");
})().catch((error) => { process.stderr.write(String(error.stack || error) + "\n"); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
