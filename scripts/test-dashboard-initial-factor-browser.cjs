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
  const checks = [], checked = (name) => { checks.push(name); process.stdout.write(`BROWSER_CHECK ${name}\n`); };
  const control = async (line) => { process.stdout.write(line + "\n"); return (await iterator.next()).value; };
  const state = async () => JSON.parse(await control("PORTICO_BROWSER_FACTOR_STATE"));
  let page;
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, serviceWorkers: "block", proxy: { server: config.Proxy }, clientCertificates: [{ origin: config.Origin, cert: Buffer.from(config.Certificate), key: Buffer.from(config.Key) }] });
    context.setDefaultTimeout(8000);
    page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const authenticator = async () => (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "usb", hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true, defaultBackupEligibility: false, defaultBackupState: false } })).authenticatorId;
    let currentKey = await authenticator();
    const requests = [], errors = [];
    let creations = 0, assertions = 0, confirms = 0, lastConfirmation;
    cdp.on("WebAuthn.credentialAdded", () => creations++);
    cdp.on("WebAuthn.credentialAsserted", () => assertions++);
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => {
      requests.push(request.url());
      if (request.url().endsWith("/factors/confirm")) { confirms++; lastConfirmation = request.postDataJSON(); }
    });
    const ready = async () => {
      await page.waitForFunction(() => document.querySelector(".inventory")?.getAttribute("aria-busy") === "false");
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText());
    };
    const navigate = async () => {
      const target = `${config.Origin}/admin#factors`;
      if (page.url() === target) await page.reload({ waitUntil: "domcontentloaded" });
      else await page.goto(target, { waitUntil: "domcontentloaded" });
      await ready();
    };
    const start = async (label = "Initial key registration") => {
      await navigate(); await page.getByRole("button", { name: label, exact: true }).click();
      assert.equal(await page.locator("#factor-preview").count(), 1);
    };
    const press = async (label) => page.getByRole("button", { name: label, exact: true }).click();
    const error = async () => page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true");
    const success = async (title) => {
      await page.waitForFunction((text) => [...document.querySelectorAll("h2")].some((node) => node.textContent === text) || document.querySelector("#feedback").dataset.error === "true", title);
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText());
      assert.equal(await page.getByRole("heading", { name: title, exact: true }).count(), 1);
    };
    const challengeEndpoint = `${config.Origin}/api/v1/admin/factors/challenge`, confirmEndpoint = `${config.Origin}/api/v1/admin/factors/confirm`;
    const expected = { Total: 0, Enabled: 0, Tested: 0, Registered: 0, Retired: 0, Tests: 0 };
    assert.deepEqual(await state(), expected);
    checked("initial browser starts with no imported or pre-registered factor");

    for (const field of ["rp", "user", "attestation", "attachment", "verification"]) {
      await start();
      await page.route(challengeEndpoint, async (route) => {
        const response = await route.fetch(), body = await response.json();
        const options = body.Challenge.Registration.publicKey;
        if (field === "rp") options.rp.id = "other.portico.test";
        if (field === "user") options.user.id = Buffer.from("different-user").toString("base64url");
        if (field === "attestation") options.attestation = "none";
        if (field === "attachment") options.authenticatorSelection.authenticatorAttachment = "platform";
        if (field === "verification") options.authenticatorSelection.userVerification = "preferred";
        await route.fulfill({ response, json: body });
      });
      await press("Register initial key"); await error();
      assert.equal(creations, 0); assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
      await page.unroute(challengeEndpoint);
    }
    checked("altered relying party, user, attestation, attachment and verification stop before native creation");

    await start();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: currentKey, enabled: false });
    const challenge = page.waitForResponse(challengeEndpoint);
    await press("Register initial key"); assert.equal((await challenge).status(), 200);
    await press("Cancel key operation"); await ready();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: currentKey, enabled: true });
    assert.equal(confirms, 0); assert.equal(creations, 0); assert.deepEqual(await state(), expected);
    checked("canceled native initial registration creates no factor or confirmation");

    const ids = [], handles = [];
    for (let index = 0; index < 2; index++) {
      if (index) {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: currentKey });
        currentKey = await authenticator();
      }
      await start();
      if (!index) {
        assert.equal(await page.evaluate(() => document.activeElement.tagName), "H2");
        await page.screenshot({ path: path.join(config.Report, "desktop-initial-key-review.png"), fullPage: true });
        await page.setViewportSize({ width: 360, height: 900 }); await page.emulateMedia({ colorScheme: "dark" });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        for (const label of ["Register initial key", "Cancel key operation"]) assert.equal((await page.getByRole("button", { name: label, exact: true }).boundingBox()).height >= 48, true);
        await page.screenshot({ path: path.join(config.Report, "mobile-initial-key-review-dark.png"), fullPage: true });
        await page.setViewportSize({ width: 1440, height: 1050 }); await page.emulateMedia({ colorScheme: "light" });
      }
      await press("Register initial key"); await success("Security key registered");
      expected.Total++; expected.Enabled++; expected.Registered++;
      assert.deepEqual(await state(), expected); assert.equal(creations, index + 1);
      const registered = (await cdp.send("WebAuthn.getCredentials", { authenticatorId: currentKey })).credentials;
      assert.equal(registered.length, 1); handles.push(registered[0].credentialId);
      const replay = await page.evaluate(async ({ endpoint, body }) => (await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).status, { endpoint: confirmEndpoint, body: lastConfirmation });
      assert.equal(replay, 403); assert.deepEqual(await state(), expected);
      await navigate();
      const untested = page.locator("tbody tr").filter({ has: page.getByText("Needs key test", { exact: true }) });
      assert.equal(await untested.count(), 1);
      const id = await untested.locator('td[data-label="Key record"]').innerText(); ids.push(id);
      checked(`initial key ${index + 1} uses native attested registration, remains untested and rejects confirmation replay`);
      if (!index) {
        await start("Add security key"); const before = confirms;
        await press("Approve adding a key"); await error();
        assert.equal(confirms, before); assert.equal(assertions, 0); assert.deepEqual(await state(), expected);
        checked("an untested initial key cannot authorize replacement registration");
      }
      await start(`Test key ${id}`); await press("Test this key"); await success("Security key test passed");
      expected.Tested++; expected.Tests++; assert.deepEqual(await state(), expected);
      checked(`initial key ${index + 1} passes its separate native exact-key test`);
    }
    assert.notEqual(ids[0], ids[1]); assert.notEqual(handles[0], handles[1]);
    await start(); const beforeThird = confirms;
    await press("Register initial key"); await error();
    assert.equal(confirms, beforeThird); assert.equal(creations, 2); assert.deepEqual(await state(), expected);
    checked("third initial registration is denied before a native response");

    await start(`Retire key ${ids[0]}`); await press("Approve retirement with backup key"); await success("Security key retired");
    expected.Enabled--; expected.Tested--; expected.Retired++; assert.deepEqual(await state(), expected);
    await start(); const beforeRetired = confirms;
    await press("Register initial key"); await error();
    assert.equal(confirms, beforeRetired); assert.equal(creations, 2); assert.deepEqual(await state(), expected);
    checked("independently created backup retires primary without reopening initial registration");

    await start(`Test key ${ids[1]}`);
    assert.equal(await control("PORTICO_BROWSER_REVOKE"), "revoked"); const beforeRevoke = confirms;
    await press("Test this key"); await error();
    assert.equal(confirms, beforeRevoke); assert.deepEqual(await state(), expected);
    checked("revoking administrator identity denies the newly registered backup over the existing browser connection");
    assert.deepEqual(await context.cookies(), []);
    assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
    assert.equal(requests.every((url) => new URL(url).origin === config.Origin), true); assert.deepEqual(errors, []);
    checked("initial flow leaves no cookies, browser storage, external page requests or script errors");
    await fs.writeFile(path.join(config.Report, "result.json"), JSON.stringify({ browser: browser.version(), playwright: require("playwright/package.json").version, checks, creations, assertions, final_state: expected, limitations: ["Both native browser credentials use isolated virtual USB keys and Chromium software attestation; this does not qualify physical keys or independent custody.", "Administrator TLS identity is provisioned by the fixture. Complete owner bootstrap, native bridge, encrypted backup and recovery remain unqualified."] }, null, 2) + "\n");
    await context.close();
  } catch (error) {
    if (page) await page.screenshot({ path: path.join(config.Report, "failure.png"), fullPage: true }).catch(() => {});
    throw error;
  } finally { await browser.close(); lines.close(); process.stdin.destroy(); }
  process.stdout.write("PORTICO_DASHBOARD_BROWSER_PASS\n");
})().catch((error) => { process.stderr.write(String(error.stack || error) + "\n"); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
