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
  const checked = (name) => { checks.push(name); process.stdout.write(`BROWSER_CHECK ${name}\n`); };
  const control = async (line) => { process.stdout.write(line + "\n"); return (await iterator.next()).value; };
  const state = async () => JSON.parse(await control("PORTICO_BROWSER_POLICY_STATE"));
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
    page.on("request", (request) => {
      requests.push(request.url());
      if (request.url().endsWith("/policy/confirm")) { confirms++; lastConfirmation = request.postDataJSON(); }
    });
    const ready = async () => {
      await page.waitForFunction(() => document.querySelector(".inventory")?.getAttribute("aria-busy") === "false");
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText());
    };
    const error = async () => { await page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true"); };
    const navigate = async (section) => {
      const target = `${config.Origin}/admin#${section}`;
      // Navigating to an unchanged hash does not refresh the document or its snapshot.
      if (page.url() === target) await page.reload({ waitUntil: "domcontentloaded" });
      else await page.goto(target, { waitUntil: "domcontentloaded" });
      await ready();
    };
    const refresh = async () => { await page.locator("#refresh").click(); await ready(); };
    const connectorChoice = async () => {
      const select = page.getByLabel("Connector", { exact: true });
      while (await select.locator(`option[value="${config.ConnectorID}"]`).count() === 0) {
        await page.getByRole("button", { name: "Next connector choices", exact: true }).click(); await ready();
      }
      await select.selectOption(config.ConnectorID);
    };
    const draft = async (name = "Browser application") => {
      await navigate("resources");
      await page.getByRole("button", { name: "Create resource", exact: true }).click(); await ready();
      await page.getByLabel("Resource name", { exact: true }).fill(name);
      await page.getByLabel("Canonical destination IP address").fill("192.168.50.11");
      await page.getByLabel("TCP port", { exact: true }).fill("8443");
      await connectorChoice();
    };
    const review = async () => { await page.getByRole("button", { name: "Review change", exact: true }).click(); await ready(); assert.equal(await page.locator("#policy-preview").count(), 1); };
    const approve = async () => {
      await page.getByRole("button", { name: "Approve with security key", exact: true }).click();
      await page.getByRole("heading", { name: "Change applied", exact: true }).waitFor();
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false");
    };
    const baseline = await state();
    assert.deepEqual(baseline, { Resources: 1, Grants: 1, Hosting: 1, Applied: 0 });

    await draft();
    const previousChoices = page.getByRole("button", { name: "Previous connector choices", exact: true });
    if (await previousChoices.isEnabled()) { await previousChoices.click(); await ready(); }
    assert.equal(await page.locator("#policy-connector option").count(), 51);
    await page.getByRole("button", { name: "Next connector choices", exact: true }).click(); await ready();
    assert.equal(await page.locator("#policy-connector option").count(), 6);
    assert.equal(await page.getByLabel("Resource name", { exact: true }).inputValue(), "Browser application");
    assert.equal(await page.getByLabel("TCP port", { exact: true }).inputValue(), "8443");
    await previousChoices.click(); await ready(); await connectorChoice();
    checked("bounded forward and backward management choices retain unsent form values");
    const previewEndpoint = `${config.Origin}/api/v1/admin/policy/preview`;
    const challengeEndpoint = `${config.Origin}/api/v1/admin/policy/challenge`;
    const confirmEndpoint = `${config.Origin}/api/v1/admin/policy/confirm`;
    await page.route(previewEndpoint, async (route) => { const response = await route.fetch(); const body = await response.json(); body.Resource.Port = 22; await route.fulfill({ response, json: body }); });
    await page.getByRole("button", { name: "Review change", exact: true }).click(); await error();
    assert.equal(await page.getByRole("button", { name: "Approve with security key" }).count(), 0);
    assert.deepEqual(await state(), baseline); assert.equal(confirms, 0);
    await page.unroute(previewEndpoint);
    checked("altered destination preview rejected before hardware ceremony or policy mutation");

    await draft(); await review();
    await page.route(challengeEndpoint, async (route) => { const response = await route.fetch(); const body = await response.json(); body.Approval.publicKey.rpId = "other.portico.test"; await route.fulfill({ response, json: body }); });
    await page.getByRole("button", { name: "Approve with security key" }).click(); await error();
    assert.equal(assertions, 0); assert.equal(confirms, 0); assert.deepEqual(await state(), baseline);
    await page.unroute(challengeEndpoint);
    checked("different relying party rejected without requesting or submitting a credential");

    await draft(); await review();
    assert.equal(await control("PORTICO_BROWSER_POLICY_CHANGE"), "policy_changed");
    await page.getByRole("button", { name: "Approve with security key" }).click(); await error();
    assert.equal(confirms, 0); assert.deepEqual(await state(), baseline);
    checked("concurrent policy change invalidates the preview before approval");

    await draft(); await review();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: false });
    const challenged = page.waitForResponse(challengeEndpoint);
    await page.getByRole("button", { name: "Approve with security key" }).click();
    assert.equal((await challenged).status(), 200);
    await page.getByRole("button", { name: "Cancel change", exact: true }).click(); await ready();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: true });
    assert.equal(await page.locator("#policy-preview").count(), 0);
    assert.equal(confirms, 0); assert.deepEqual(await state(), baseline);
    checked("cancelling an in-flight native credential request submits no approval");

    await draft(); await review();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: false });
    const navigationChallenge = page.waitForResponse(challengeEndpoint);
    await page.getByRole("button", { name: "Approve with security key" }).click();
    assert.equal((await navigationChallenge).status(), 200);
    await page.locator('nav a[data-section="users"]').click(); await ready();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: true });
    assert.equal(await page.locator("#policy-preview").count(), 0); assert.equal(confirms, 0); assert.deepEqual(await state(), baseline);
    checked("section navigation discards the preview and aborts pending hardware approval");

    for (const [name, override] of [["user verification", { isBadUV: true }], ["signature", { isBogusSignature: true }]]) {
      await draft(); await review();
      await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId, ...override });
      const before = confirms;
      await page.getByRole("button", { name: "Approve with security key" }).click(); await error();
      assert.equal(confirms, before + 1); assert.equal(await page.getByRole("button", { name: "Approve with security key" }).isDisabled(), true);
      assert.deepEqual(await state(), baseline);
      await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId, isBadUV: false, isBadUP: false, isBogusSignature: false });
      checked(`real controller rejects native virtual authenticator response with invalid ${name}`);
    }

    const name = '<img src=x onerror="globalThis.policyExecuted=true">';
    await draft(name); await review();
    assert.match(await page.locator("#policy-preview").innerText(), /192\.168\.50\.11:8443 \/ TCP/);
    assert.equal(await page.locator("#policy-preview img").count(), 0);
    assert.equal(await page.evaluate(() => globalThis.policyExecuted), undefined);
    assert.equal(await page.evaluate(() => document.activeElement.tagName), "H2");
    assert.deepEqual(await state(), baseline);
    await page.screenshot({ path: path.join(config.Report, "desktop-preview.png"), fullPage: true });
    await page.setViewportSize({ width: 360, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    for (const target of ["Approve with security key", "Cancel change"]) assert.equal((await page.getByRole("button", { name: target, exact: true }).boundingBox()).height >= 48, true);
    await page.emulateMedia({ colorScheme: "dark" });
    await page.screenshot({ path: path.join(config.Report, "mobile-preview-dark.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1050 }); await page.emulateMedia({ colorScheme: "light" });
    checked("exact readable preview, safe hostile text, keyboard focus and 360px dark reflow");
    await page.getByRole("button", { name: "Approve with security key" }).focus(); await page.keyboard.press("Enter");
    await page.getByRole("heading", { name: "Change applied", exact: true }).waitFor();
    let expected = { ...baseline, Resources: 2, Applied: 1 };
    assert.deepEqual(await state(), expected);
    assert.equal(assertions >= 3, true);
    const replay = await page.evaluate(async ({ endpoint, body }) => (await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).status, { endpoint: confirmEndpoint, body: lastConfirmation });
    assert.equal(replay, 403); assert.deepEqual(await state(), expected);
    checked("real browser WebAuthn creates one resource, and the controller rejects assertion replay");

    await page.getByRole("button", { name: "Return to inventory" }).click(); await ready();
    const row = page.locator("tbody tr").filter({ has: page.getByText(name, { exact: true }) });
    const resourceID = await row.locator('td[data-label="Resource"] .record-id').innerText();
    assert.equal(await row.locator('td[data-label="Revision"]').innerText(), "1");
    await row.getByRole("button", { name: `Revise ${name}`, exact: true }).click(); await ready();
    await connectorChoice();
    await page.getByLabel("TCP port", { exact: true }).fill("9000"); await review();
    assert.match(await page.locator("#policy-preview").innerText(), /Current destination/);
    assert.match(await page.locator("#policy-preview").innerText(), /192\.168\.50\.11:8443/);
    assert.match(await page.locator("#policy-preview").innerText(), /192\.168\.50\.11:9000/);
    await approve(); expected.Applied++; assert.deepEqual(await state(), expected);
    checked("resource revision approval shows old and new tuples and preserves resource identity");

    for (const [section, button, field] of [["hosting", "Add hosting permission", "Hosting"], ["grants", "Add device grant", "Grants"]]) {
      await navigate(section); await page.getByRole("button", { name: button, exact: true }).click(); await ready();
      if (section === "grants") await page.getByLabel("Device", { exact: true }).selectOption(config.DeviceID);
      await page.getByLabel("Resource", { exact: true }).selectOption(resourceID);
      const from = new Date(Date.now() - 60000).toISOString().slice(0, 16), until = new Date(Date.now() + 600000).toISOString().slice(0, 16);
      await page.getByLabel("Valid from (UTC)", { exact: true }).fill(from);
      await page.getByLabel("Valid until (UTC)", { exact: true }).fill(until);
      await review();
      assert.match(await page.locator("#policy-preview").innerText(), /192\.168\.50\.11:9000/);
      assert.equal(await page.locator("#policy-preview").getByText("2", { exact: true }).count(), 1);
      assert.match(await page.locator("#policy-preview").innerText(), new RegExp(until));
      await approve(); expected.Applied++; expected[field]++; assert.deepEqual(await state(), expected);
      await page.getByRole("button", { name: "Return to inventory" }).click(); await ready();
      const permission = page.locator("tbody tr").filter({ has: page.getByText(resourceID, { exact: true }) });
      assert.equal(await permission.count(), 1); assert.equal(await permission.locator('td[data-label="Revision"]').innerText(), "2");
      checked(`native security-key approval applies exact revision and UTC interval for ${section}`);
    }

    await draft("Uncertain response fixture"); await review();
    await page.route(confirmEndpoint, async (route) => { const response = await route.fetch(); assert.equal(response.status(), 200); await route.abort("failed"); });
    const beforeUnknown = confirms;
    await page.getByRole("button", { name: "Approve with security key" }).click(); await error();
    assert.match(await page.locator("#feedback").innerText(), /may have been applied/);
    assert.equal(confirms, beforeUnknown + 1); assert.equal(await page.getByRole("button", { name: "Approve with security key" }).isDisabled(), true);
    expected.Resources++; expected.Applied++; assert.deepEqual(await state(), expected);
    await page.unroute(confirmEndpoint); await refresh();
    assert.equal(await page.getByText("Uncertain response fixture", { exact: true }).count(), 1);
    checked("lost confirmation response reports uncertain outcome and never retries the committed mutation");

    await draft("Revoked administrator fixture"); await review();
    assert.equal(await control("PORTICO_BROWSER_REVOKE"), "revoked");
    const beforeRevoke = confirms;
    await page.getByRole("button", { name: "Approve with security key" }).click(); await error();
    assert.equal(confirms, beforeRevoke); assert.deepEqual(await state(), expected);
    checked("live administrator revocation denies a previously displayed preview");

    assert.deepEqual(await context.cookies(), []);
    assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
    assert.equal(requests.every((url) => new URL(url).origin === config.Origin), true); assert.deepEqual(errors, []);
    checked("no cookie, persistent browser state, external page request or script error");
    await fs.writeFile(path.join(config.Report, "result.json"), JSON.stringify({ browser: browser.version(), playwright: require("playwright/package.json").version, checks, assertions, final_state: expected, limitations: ["Virtual USB P256 authenticator with software attestation fixtures; no physical key model qualification.", "Private TLS browser fixture uses Playwright client-certificate proxy; no native administrator bridge or platform custody qualification."] }, null, 2) + "\n");
    await context.close();
  } catch (error) {
    if (page) await page.screenshot({ path: path.join(config.Report, "failure.png"), fullPage: true }).catch(() => {});
    throw error;
  } finally { await browser.close(); lines.close(); process.stdin.destroy(); }
  process.stdout.write("PORTICO_DASHBOARD_BROWSER_PASS\n");
})().catch((error) => { process.stderr.write(String(error.stack || error) + "\n"); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
