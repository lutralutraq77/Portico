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
  const state = async () => JSON.parse(await control("PORTICO_BROWSER_LIFECYCLE_STATE"));
  let page;
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, colorScheme: "light", serviceWorkers: "block", proxy: { server: config.Proxy }, clientCertificates: [{ origin: config.Origin, cert: Buffer.from(config.Certificate), key: Buffer.from(config.Key) }] });
    context.setDefaultTimeout(8000);
    page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "usb", hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true, defaultBackupEligibility: false, defaultBackupState: false } });
    await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId: config.CredentialID, isResidentCredential: false, rpId: "admin.portico.test", privateKey: config.CredentialKey, signCount: config.SignCount, userHandle: config.UserHandle } });
    const errors = [], requests = [];
    let assertions = 0, confirms = 0, lastConfirmation;
    cdp.on("WebAuthn.credentialAsserted", () => assertions++);
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => { requests.push(request.url()); if (request.url().endsWith("/policy/confirm")) { confirms++; lastConfirmation = request.postDataJSON(); } });
    const ready = async () => { await page.waitForFunction(() => document.querySelector(".inventory")?.getAttribute("aria-busy") === "false"); assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText()); };
    const error = async () => page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true");
    const navigate = async (section) => { const target = `${config.Origin}/admin#${section}`; if (page.url() === target) await page.reload({ waitUntil: "domcontentloaded" }); else await page.goto(target, { waitUntil: "domcontentloaded" }); await ready(); };
    const press = async (name) => page.getByRole("button", { name, exact: true }).click();
    const findRow = async (section, id) => {
      await navigate(section);
      const row = page.locator("tbody tr").filter({ has: page.getByText(id, { exact: true }) });
      for (let attempt = 0; attempt < 3 && await row.count() === 0; attempt++) { assert.equal(await page.locator("#next").isEnabled(), true); await page.locator("#next").click(); await ready(); }
      assert.equal(await row.count(), 1); return row;
    };
    const add = async (entity, name) => { await navigate(entity === "user" ? "users" : `${entity}s`); await press(`Add ${entity}`); await ready(); await page.getByLabel(`${entity[0].toUpperCase() + entity.slice(1)} name`, { exact: true }).fill(name); };
    const review = async () => { await press("Review change"); await ready(); assert.equal(await page.locator("#policy-preview").count(), 1); };
    const approve = async () => { await press("Approve with security key"); await page.waitForFunction(() => [...document.querySelectorAll("h2")].some((node) => node.textContent === "Change applied") || document.querySelector("#feedback").dataset.error === "true"); assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText()); };
    const targetID = async () => page.locator('#policy-preview dt').filter({ hasText: /^Record ID$/ }).evaluate((node) => node.nextElementSibling.textContent);
    const previewEndpoint = `${config.Origin}/api/v1/admin/policy/preview`, challengeEndpoint = `${config.Origin}/api/v1/admin/policy/challenge`, confirmEndpoint = `${config.Origin}/api/v1/admin/policy/confirm`;
    let expected = await state();
    assert.equal(expected.Users, 56); assert.equal(expected.Devices, 2); assert.equal(expected.Connectors, 1); assert.equal(expected.Applied, 0);

    await add("user", "Draft user");
    await page.route(previewEndpoint, async (route) => { const response = await route.fetch(), body = await response.json(); body.Lifecycle.Name = "Different user"; await route.fulfill({ response, json: body }); });
    await press("Review change"); await error();
    assert.equal(await page.locator("#policy-preview").count(), 0); assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    await page.unroute(previewEndpoint);
    checked("altered lifecycle name is rejected before security-key approval");

    for (const [entity, id] of [["user", config.AdministratorUserID], ["device", config.AdministratorDeviceID]]) {
      const row = await findRow(`${entity}s`, id);
      await row.getByRole("button", { name: /^Revoke access for / }).click(); await ready(); await press("Review change"); await error();
      assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    }
    checked("current administrator user and device cannot be revoked through their own session");

    await add("user", "Stale user"); await review();
    assert.equal(await control("PORTICO_BROWSER_POLICY_CHANGE"), "policy_changed"); expected.Users++; expected.EnabledUsers++;
    await press("Approve with security key"); await error(); assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    checked("concurrent policy change invalidates a reviewed lifecycle operation");

    await add("user", "Cancelled user"); await review();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: false });
    const challenged = page.waitForResponse(challengeEndpoint);
    await press("Approve with security key"); assert.equal((await challenged).status(), 200);
    await press("Cancel change"); await ready();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: true });
    assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    checked("cancelling a native lifecycle approval does not commit a record");

    const unsafeName = '<img src=x onerror="globalThis.lifecycleExecuted=true">';
    await add("user", unsafeName); await review();
    assert.equal(await page.locator("#policy-preview img").count(), 0); assert.equal(await page.evaluate(() => globalThis.lifecycleExecuted), undefined);
    assert.equal(await page.evaluate(() => document.activeElement.tagName), "H2");
    const userID = await targetID();
    await approve(); expected.Users++; expected.EnabledUsers++; expected.Applied++; assert.deepEqual(await state(), expected);
    const replay = await page.evaluate(async ({ endpoint, body }) => (await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).status, { endpoint: confirmEndpoint, body: lastConfirmation });
    assert.equal(replay, 403); assert.deepEqual(await state(), expected);
    checked("native key approval creates the exact user once and renders hostile names as text");

    await add("device", "Browser laptop");
    await page.getByLabel("Platform", { exact: true }).selectOption("linux");
    const until = new Date(Date.now() + 1200000).toISOString().slice(0, 16);
    await page.getByLabel("Device authorization expires (UTC)").fill(until);
    assert.equal(await page.locator("#policy-user option").count(), 51);
    await press("Next user choices"); await ready();
    assert.equal(await page.getByLabel("Device name", { exact: true }).inputValue(), "Browser laptop");
    assert.equal(await page.getByLabel("Device authorization expires (UTC)").inputValue(), until);
    await press("Previous user choices"); await ready();
    if (await page.locator(`#policy-user option[value="${userID}"]`).count() === 0) { await press("Next user choices"); await ready(); }
    await page.getByLabel("User", { exact: true }).selectOption(userID);
    await page.route(previewEndpoint, async (route) => { const response = await route.fetch(), body = await response.json(); body.Lifecycle.UserID = config.UserID; await route.fulfill({ response, json: body }); });
    const beforeOwner = confirms;
    await press("Review change"); await error(); assert.equal(confirms, beforeOwner); assert.deepEqual(await state(), expected); await page.unroute(previewEndpoint);
    checked("paged owner choices retain unsent values and a changed device owner is rejected");

    await add("device", "Browser laptop");
    await page.getByLabel("Device authorization expires (UTC)").fill(until);
    if (await page.locator(`#policy-user option[value="${userID}"]`).count() === 0) { await press("Next user choices"); await ready(); }
    await page.getByLabel("User", { exact: true }).selectOption(userID); await review();
    assert.match(await page.locator("#policy-preview").innerText(), new RegExp(userID)); assert.match(await page.locator("#policy-preview").innerText(), new RegExp(until));
    const deviceID = await targetID();
    await approve(); expected.Devices++; expected.EnabledDevices++; expected.Applied++; assert.deepEqual(await state(), expected);
    await add("connector", "Browser connector"); await review(); assert.match(await page.locator("#policy-preview").innerText(), /unreported/);
    const connectorID = await targetID();
    await approve(); expected.Connectors++; expected.EnabledConnectors++; expected.Applied++; assert.deepEqual(await state(), expected);
    checked("device and connector creation preserve owner/expiry and create no enrollment, grant or hosting");

    for (const [entity, id] of [["user", userID], ["device", deviceID], ["connector", connectorID]]) {
      const row = await findRow(`${entity}s`, id);
      await row.getByRole("button", { name: /^Rename for / }).click(); await ready();
      await page.getByLabel(`${entity[0].toUpperCase() + entity.slice(1)} name`, { exact: true }).fill(`Updated ${entity}`); await review();
      assert.match(await page.locator("#policy-preview").innerText(), /Current name/); assert.match(await page.locator("#policy-preview").innerText(), /Proposed name/);
      assert.equal(await targetID(), id); await approve(); expected.Applied++; assert.deepEqual(await state(), expected);
    }
    checked("native approvals rename user, device and connector while retaining their identity IDs");

    let row = await findRow("users", userID);
    await row.getByRole("button", { name: /^Rename for / }).click(); await ready();
    await page.getByLabel("User name", { exact: true }).fill("Uncertain renamed user"); await review();
    await page.route(confirmEndpoint, async (route) => { const response = await route.fetch(); assert.equal(response.status(), 200); await route.abort("failed"); });
    const beforeLost = confirms;
    await press("Approve with security key"); await error();
    assert.match(await page.locator("#feedback").innerText(), /may have been applied/); assert.equal(confirms, beforeLost + 1); assert.equal(await page.getByRole("button", { name: "Approve with security key", exact: true }).isDisabled(), true);
    expected.Applied++; assert.deepEqual(await state(), expected); await page.unroute(confirmEndpoint);
    checked("lost lifecycle confirmation remains uncertain and is never automatically retried");

    for (const [entity, id] of [["device", deviceID], ["connector", connectorID], ["user", userID]]) {
      row = await findRow(`${entity}s`, id); await row.getByRole("button", { name: /^Revoke access for / }).click(); await ready(); await review();
      assert.match(await page.locator("#policy-preview").innerText(), /Dependent sessions|dependent sessions/);
      if (entity === "device") {
        await page.screenshot({ path: path.join(config.Report, "desktop-revocation.png"), fullPage: true });
        await page.setViewportSize({ width: 360, height: 900 }); await page.emulateMedia({ colorScheme: "dark" });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        for (const label of ["Approve with security key", "Cancel change"]) assert.equal((await page.getByRole("button", { name: label, exact: true }).boundingBox()).height >= 48, true);
        await page.screenshot({ path: path.join(config.Report, "mobile-revocation-dark.png"), fullPage: true });
        await page.setViewportSize({ width: 1440, height: 1050 }); await page.emulateMedia({ colorScheme: "light" });
      }
      await approve(); expected[`Enabled${entity[0].toUpperCase() + entity.slice(1)}s`]--; expected.Applied++; assert.deepEqual(await state(), expected);
      row = await findRow(`${entity}s`, id); assert.equal(await row.getByRole("button", { name: /^Rename for / }).isDisabled(), true); assert.equal(await row.getByRole("button", { name: /^Revoke access for / }).isDisabled(), true);
    }
    checked("revocation reviews name and identity, retains disabled tombstones and prevents reuse");
    checked("revocation review reflows at 360px with 48px controls in dark mode");

    row = await findRow("devices", config.DeviceID);
    await row.getByRole("button", { name: /^Revoke access for / }).click(); await ready(); await review();
    assert.equal(await control("PORTICO_BROWSER_LIFECYCLE_ACTIVE"), "active");
    await approve(); expected.EnabledDevices--; expected.Applied++;
    assert.equal(await control("PORTICO_BROWSER_LIFECYCLE_REVOKED"), "authority_removed"); assert.deepEqual(await state(), expected);
    checked("browser device revocation removes real active renewal/new-session authority and enqueues cancellation");

    await add("user", "Revoked administrator draft"); await review();
    assert.equal(await control("PORTICO_BROWSER_REVOKE"), "revoked"); expected.EnabledDevices--;
    const beforeRevoke = confirms;
    await press("Approve with security key"); await error(); assert.equal(confirms, beforeRevoke); assert.deepEqual(await state(), expected);
    checked("live administrator revocation denies a previously displayed lifecycle preview");

    assert.deepEqual(await context.cookies(), []); assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
    assert.equal(requests.every((url) => new URL(url).origin === config.Origin), true); assert.deepEqual(errors, []);
    checked("no cookies, persistent browser state, external page requests or script errors");
    await fs.writeFile(path.join(config.Report, "result.json"), JSON.stringify({ browser: browser.version(), playwright: require("playwright/package.json").version, checks, assertions, final_state: expected, limitations: ["Virtual USB key and ephemeral administrator TLS proxy; physical key custody and native administrator delivery remain unqualified.", "Revocation proves live controller authority and queued cancellation; destination socket termination has separate runtime qualification.", "Record creation does not provide enrollment invitations or complete a supported client installation."] }, null, 2) + "\n");
    await context.close();
  } catch (error) {
    if (page) { process.stderr.write(JSON.stringify(await page.evaluate(() => ({ feedback: document.querySelector("#feedback")?.textContent }))) + "\n"); await page.screenshot({ path: path.join(config.Report, "failure.png"), fullPage: true }).catch(() => {}); }
    throw error;
  } finally { await browser.close(); lines.close(); process.stdin.destroy(); }
  process.stdout.write("PORTICO_DASHBOARD_BROWSER_PASS\n");
})().catch((error) => { process.stderr.write(String(error.stack || error) + "\n"); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
