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
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, colorScheme: "light", serviceWorkers: "block", proxy: { server: config.Proxy }, clientCertificates: [{ origin: config.Origin, cert: Buffer.from(config.Certificate), key: Buffer.from(config.Key) }] });
    context.setDefaultTimeout(8000);
    page = await context.newPage();
    // Observe errors from the real browser implementation without changing its
    // arguments, return value or verification behavior. Never retain a response.
    await page.addInitScript(() => {
      for (const method of ["get", "create"]) {
        const original = CredentialsContainer.prototype[method];
        CredentialsContainer.prototype[method] = async function (...args) {
          try { return await Reflect.apply(original, this, args); }
          catch (error) { globalThis.factorNativeError = { method, name: error.name }; throw error; }
        };
      }
    });
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const authenticator = async () => (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "usb", hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true, defaultBackupEligibility: false, defaultBackupState: false } })).authenticatorId;
    // Model physically swapping USB keys. Multiple simultaneously responding
    // software devices can race discovery and obscure which key was selected.
    const primary = await authenticator();
    for (const [authenticatorId, credentialId, privateKey, signCount] of [[primary, config.CredentialID, config.CredentialKey, config.SignCount]]) {
      await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId, privateKey, signCount, isResidentCredential: false, rpId: "admin.portico.test", userHandle: config.UserHandle } });
    }
    const errors = [], requests = [];
    let assertions = 0, creations = 0, confirms = 0, lastConfirmation;
    cdp.on("WebAuthn.credentialAsserted", () => assertions++);
    cdp.on("WebAuthn.credentialAdded", () => creations++);
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => {
      requests.push(request.url());
      if (request.url().endsWith("/factors/confirm")) { confirms++; lastConfirmation = request.postDataJSON(); }
    });
    const ready = async () => {
      await page.waitForFunction(() => document.querySelector(".inventory")?.getAttribute("aria-busy") === "false");
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText());
    };
    const error = async () => page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true");
    const navigate = async (section = "factors") => {
      const target = `${config.Origin}/admin#${section}`;
      if (page.url() === target) await page.reload({ waitUntil: "domcontentloaded" });
      else await page.goto(target, { waitUntil: "domcontentloaded" });
      await ready();
    };
    const row = (id) => page.locator("tbody tr").filter({ has: page.getByText(id, { exact: true }) });
    const start = async (kind, id = config.PrimaryFactorID) => {
      await navigate();
      const label = { test: `Test key ${id}`, retire: `Retire key ${id}`, add: "Add security key", initial: "Initial key registration" }[kind];
      await page.getByRole("button", { name: label, exact: true }).click();
      assert.equal(await page.locator("#factor-preview").count(), 1);
    };
    const press = async (label) => page.getByRole("button", { name: label, exact: true }).click();
    const success = async (title) => {
      await page.waitForFunction((text) => [...document.querySelectorAll("h2")].some((node) => node.textContent === text) || document.querySelector("#feedback").dataset.error === "true", title);
      assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", JSON.stringify({ feedback: await page.locator("#feedback").innerText(), nativeError: await page.evaluate(() => globalThis.factorNativeError), assertions, creations, confirms }));
      assert.equal(await page.getByRole("heading", { name: title, exact: true }).count(), 1);
    };
    const challengeEndpoint = `${config.Origin}/api/v1/admin/factors/challenge`, confirmEndpoint = `${config.Origin}/api/v1/admin/factors/confirm`;
    let expected = { Total: 2, Enabled: 2, Tested: 2, Registered: 2, Retired: 0, Tests: 2 };
    assert.deepEqual(await state(), expected);
    await navigate("security");
    await page.getByRole("link", { name: "Security keys", exact: true }).click(); await ready();
    assert.equal(await page.locator("tbody tr").count(), 2);
    assert.equal(await page.locator('nav [data-section="security"]').getAttribute("aria-current"), "page");
    const visible = await page.locator("#records").innerText();
    for (const value of [config.CredentialID, config.BackupCredentialID]) assert.equal(visible.includes(value), false);
    checked("security navigation lists only key metadata without credential handles");

    for (const field of ["Kind", "FactorID", "PolicyRevision", "rpId"]) {
      await start("test");
      await page.route(challengeEndpoint, async (route) => {
        const response = await route.fetch(), body = await response.json();
        if (field === "rpId") body.Challenge.Approval.publicKey.rpId = "other.portico.test";
        else if (field === "Kind") body.Kind = "disable-factor";
        else if (field === "FactorID") body.FactorID = config.BackupFactorID;
        else body.PolicyRevision++;
        await route.fulfill({ response, json: body });
      });
      await press("Test this key"); await error();
      assert.equal(assertions, 0); assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
      await page.unroute(challengeEndpoint);
    }
    checked("changed operation, target, revision and relying party stop before native assertion");

    await start("test");
    assert.equal(await control("PORTICO_BROWSER_POLICY_CHANGE"), "policy_changed");
    await press("Test this key"); await error();
    assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    checked("concurrent policy change denies the previously reviewed key operation");

    for (const leave of ["cancel", "navigate"]) {
      await start("test");
      await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: primary, enabled: false });
      const challenge = page.waitForResponse(challengeEndpoint);
      await press("Test this key"); assert.equal((await challenge).status(), 200);
      if (leave === "cancel") await press("Cancel key operation");
      else await page.locator('nav [data-section="users"]').click();
      await ready();
      await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId: primary, enabled: true });
      assert.equal(confirms, 0); assert.equal(await page.locator("#factor-preview").count(), 0); assert.deepEqual(await state(), expected);
    }
    checked("cancellation and navigation abort native key requests without a confirmation");

    await start("test");
    await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId: primary, isBadUV: true });
    await press("Test this key"); await error();
    assert.equal(confirms, 1, JSON.stringify({ feedback: await page.locator("#feedback").innerText(), nativeError: await page.evaluate(() => globalThis.factorNativeError) })); assert.deepEqual(await state(), expected);
    await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId: primary, isBadUV: false });
    checked("real controller rejects a native key proof without user verification");

    await start("test");
    assert.match(await page.locator("#factor-preview").innerText(), new RegExp(config.PrimaryFactorID));
    assert.equal(await page.evaluate(() => document.activeElement.tagName), "H2");
    await page.screenshot({ path: path.join(config.Report, "desktop-key-review.png"), fullPage: true });
    await page.setViewportSize({ width: 360, height: 900 }); await page.emulateMedia({ colorScheme: "dark" });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    for (const label of ["Test this key", "Cancel key operation"]) assert.equal((await page.getByRole("button", { name: label, exact: true }).boundingBox()).height >= 48, true);
    await page.screenshot({ path: path.join(config.Report, "mobile-key-review-dark.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1050 }); await page.emulateMedia({ colorScheme: "light" });
    await page.getByRole("button", { name: "Test this key", exact: true }).focus(); await page.keyboard.press("Enter");
    await success("Security key test passed"); expected.Tests++; assert.deepEqual(await state(), expected);
    const replay = await page.evaluate(async ({ endpoint, body }) => (await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).status, { endpoint: confirmEndpoint, body: lastConfirmation });
    assert.equal(replay, 403); assert.deepEqual(await state(), expected);
    checked("exact key test uses native assertion, keyboard activation and one-use confirmation");
    checked("key review focuses its heading and reflows at 360px in dark mode");

    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: primary });
    const backup = await authenticator();
    await cdp.send("WebAuthn.addCredential", { authenticatorId: backup, credential: { credentialId: config.BackupCredentialID, privateKey: config.BackupCredentialKey, signCount: config.BackupSignCount, isResidentCredential: false, rpId: "admin.portico.test", userHandle: config.UserHandle } });
    // Importing a pre-registered key is fixture setup, not native registration.
    creations = 0;
    await start("retire"); await press("Approve retirement with backup key"); await success("Security key retired");
    expected.Enabled--; expected.Tested--; expected.Retired++; assert.deepEqual(await state(), expected);
    await navigate();
    assert.equal(await row(config.PrimaryFactorID).getByRole("button", { name: `Test key ${config.PrimaryFactorID}`, exact: true }).isDisabled(), true);
    checked("different native backup key retires primary and retired row cannot start a key test");

    await start("initial"); await press("Register initial key"); await error();
    assert.equal(creations, 0); assert.deepEqual(await state(), expected);
    checked("retirement does not reopen the initial two-key registration allowance");

    // Existing keys approve, then a separate empty virtual USB device performs
    // native create. Production code receives an ordinary packed attestation.
    await start("add"); await press("Approve adding a key"); await success("Connect the new security key");
    assert.equal(creations, 0); assert.deepEqual(await state(), expected);
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: backup });
    const replacement = await authenticator();
    await press("Register new key");
    await page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true" || [...document.querySelectorAll("h2")].some((node) => node.textContent === "Security key registered"));
    if (await page.locator("#feedback").getAttribute("data-error") === "true") process.stderr.write(await control("PORTICO_BROWSER_FACTOR_DIAG " + JSON.stringify(lastConfirmation)) + "\n");
    await success("Security key registered");
    expected.Total++; expected.Enabled++; expected.Registered++; assert.deepEqual(await state(), expected);
    assert.equal(creations, 1);
    const registered = (await cdp.send("WebAuthn.getCredentials", { authenticatorId: replacement })).credentials;
    assert.equal(registered.length, 1);
    await navigate();
    const newRow = page.locator("tbody tr").filter({ has: page.getByText("Needs key test", { exact: true }) });
    assert.equal(await newRow.count(), 1);
    const replacementID = await newRow.locator('td[data-label="Key record"]').innerText();
    checked("separate native create registers the replacement with attestation but leaves it untested");

    await start("test", replacementID); await press("Test this key"); await success("Security key test passed");
    expected.Tested++; expected.Tests++; assert.deepEqual(await state(), expected);
    checked("newly created browser credential passes its independent exact-key test");

    await start("test", replacementID);
    await page.route(confirmEndpoint, async (route) => { const response = await route.fetch(); assert.equal(response.status(), 200); await route.abort("failed"); });
    const beforeLost = confirms;
    await press("Test this key"); await error();
    assert.match(await page.locator("#feedback").innerText(), /may have been applied/);
    assert.equal(confirms, beforeLost + 1); assert.equal(await page.getByRole("button", { name: "Test this key", exact: true }).isDisabled(), true);
    expected.Tests++; assert.deepEqual(await state(), expected); await page.unroute(confirmEndpoint);
    checked("lost key confirmation reports uncertainty without replaying the committed operation");

    await start("retire", config.BackupFactorID); await press("Approve retirement with backup key"); await success("Security key retired");
    expected.Enabled--; expected.Tested--; expected.Retired++; assert.deepEqual(await state(), expected);
    await start("retire", replacementID); const beforeLast = confirms;
    await press("Approve retirement with backup key"); await error();
    assert.equal(confirms, beforeLast); assert.deepEqual(await state(), expected);
    checked("replacement can authorize retirement but final enabled key cannot retire itself");

    await start("test", replacementID);
    assert.equal(await control("PORTICO_BROWSER_REVOKE"), "revoked");
    const beforeRevoke = confirms;
    await press("Test this key"); await error();
    assert.equal(confirms, beforeRevoke); assert.deepEqual(await state(), expected);
    checked("live administrator revocation denies the key operation over the existing browser context");

    assert.deepEqual(await context.cookies(), []);
    assert.deepEqual(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })), { local: 0, session: 0 });
    assert.equal(requests.every((url) => new URL(url).origin === config.Origin), true); assert.deepEqual(errors, []);
    checked("no cookies, browser storage, external page requests or script errors");
    await fs.writeFile(path.join(config.Report, "result.json"), JSON.stringify({ browser: browser.version(), playwright: require("playwright/package.json").version, checks, assertions, creations, final_state: expected, limitations: ["Virtual USB devices and the public Chromium software attestation signer are isolated test fixtures, not physical security-key qualification.", "Private TLS uses an ephemeral client-certificate proxy; native administrator bridge, platform custody and complete bootstrap remain unqualified."] }, null, 2) + "\n");
    await context.close();
  } catch (error) {
    if (page) process.stderr.write(JSON.stringify(await page.evaluate(() => ({ feedback: document.querySelector("#feedback")?.textContent, nativeError: globalThis.factorNativeError }))).concat("\n"));
    if (page) await page.screenshot({ path: path.join(config.Report, "failure.png"), fullPage: true }).catch(() => {});
    throw error;
  } finally { await browser.close(); lines.close(); process.stdin.destroy(); }
  process.stdout.write("PORTICO_DASHBOARD_BROWSER_PASS\n");
})().catch((error) => { process.stderr.write(String(error.stack || error) + "\n"); process.exitCode = 1; lines.close(); process.stdin.destroy(); });
