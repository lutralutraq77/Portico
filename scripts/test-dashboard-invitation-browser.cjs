"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const readline = require("node:readline");
const { chromium } = require("playwright");
const iterator = readline.createInterface({ input: process.stdin })[Symbol.asyncIterator]();

(async () => {
  const config = JSON.parse((await iterator.next()).value);
  await fs.mkdir(config.Report, { recursive: true });
  const browser = await chromium.launch({ executablePath: config.Browser, headless: true, args: ["--disable-background-networking"] });
  const checks = [], checked = (name) => { checks.push(name); process.stdout.write(`BROWSER_CHECK ${name}\n`); };
  const control = async (line) => { process.stdout.write(line + "\n"); return (await iterator.next()).value; };
  const state = async () => JSON.parse(await control("PORTICO_BROWSER_INVITATION_STATE"));
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, colorScheme: "light", serviceWorkers: "block", proxy: { server: config.Proxy }, clientCertificates: [{ origin: config.Origin, cert: Buffer.from(config.Certificate), key: Buffer.from(config.Key) }] });
    context.setDefaultTimeout(8000);
    const page = await context.newPage(), cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "usb", hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true, defaultBackupEligibility: false, defaultBackupState: false } });
    await cdp.send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId: config.CredentialID, isResidentCredential: false, rpId: "admin.portico.test", privateKey: config.CredentialKey, signCount: config.SignCount, userHandle: config.UserHandle } });
    const errors = [], requests = [];
    const challengeEndpoint = `${config.Origin}/api/v1/admin/invitations/challenge`, confirmEndpoint = `${config.Origin}/api/v1/admin/invitations/confirm`;
    let assertions = 0, confirms = 0, lastConfirmation;
    cdp.on("WebAuthn.credentialAsserted", () => assertions++);
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("request", (request) => { requests.push(request.url()); if (request.url() === confirmEndpoint) { confirms++; lastConfirmation = request.postDataJSON(); } });
    const ready = async () => { await page.waitForFunction(() => document.querySelector(".inventory")?.getAttribute("aria-busy") === "false"); assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText()); };
    const error = async () => page.waitForFunction(() => document.querySelector("#feedback").dataset.error === "true");
    const press = async (name) => page.getByRole("button", { name, exact: true }).click();
    const navigate = async () => { await page.goto(`${config.Origin}/admin#enrollments`, { waitUntil: "domcontentloaded" }); await press("Refresh"); await ready(); };
    const draft = async (profile = "device") => {
      await navigate(); await press(`Invite ${profile}`); await ready();
      await page.getByLabel("Issuer", { exact: true }).selectOption(profile === "device" ? config.DeviceIssuerID : config.ConnectorIssuerID);
      await page.getByLabel(profile === "device" ? "Device" : "Connector", { exact: true }).selectOption(profile === "device" ? config.DeviceID : config.ConnectorID);
      await page.getByLabel("Invitation expires (UTC, within one hour)").fill(new Date(Date.now() + 600000).toISOString().slice(0, 16));
      await page.getByLabel("Issued identity expires (UTC)").fill(new Date(Date.now() + 1200000).toISOString().slice(0, 16));
    };
    const review = async () => { await press("Review change"); await ready(); assert.equal(await page.locator("#invitation-preview").count(), 1); };
    const id = async () => page.locator("#invitation-preview dt").filter({ hasText: /^Enrollment ID$/ }).evaluate((node) => node.nextElementSibling.textContent);
    const approve = async (title) => { await press("Approve with security key"); await page.waitForFunction((title) => [...document.querySelectorAll("h2")].some((node) => node.textContent === title) || document.querySelector("#feedback").dataset.error === "true", title); assert.equal(await page.locator("#feedback").getAttribute("data-error"), "false", await page.locator("#feedback").innerText()); };
    const revokeReview = async (target) => { await navigate(); await page.getByRole("button", { name: `Revoke enrollment ${target}`, exact: true }).click(); await ready(); await review(); };
    let expected = await state();
    assert.deepEqual(expected, { Total: 2, Invited: 0, Active: 2, Revoked: 0 });

    await draft();
    await page.route(challengeEndpoint, async (route) => { const response = await route.fetch(), body = await response.json(); body.Invitation.IssuerID = config.ConnectorIssuerID; await route.fulfill({ response, json: body }); });
    await press("Review change"); await error();
    assert.equal(await page.locator("#invitation-preview").count(), 0); assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    await page.unroute(challengeEndpoint);
    checked("changed issuer in the invitation review is rejected before native approval");

    await draft(); await review();
    assert.equal(await page.locator("#invitation-secret").count(), 0); assert.deepEqual(await state(), expected);
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: false });
    await press("Approve with security key"); await press("Cancel change"); await ready();
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: true });
    assert.equal(confirms, 0); assert.deepEqual(await state(), expected);
    checked("review creates no enrollment or secret and cancellation submits no native proof");

    await draft(); await review();
    assert.equal(await control("PORTICO_BROWSER_POLICY_CHANGE"), "policy_changed");
    await press("Approve with security key"); await error(); assert.deepEqual(await state(), expected);
    checked("a native invitation proof is rejected after concurrent policy changes");

    await draft(); await review();
    await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: false });
    await press("Approve with security key"); await error(); assert.deepEqual(await state(), expected);
    await cdp.send("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: true });
    checked("actual controller rejects invitation approval without native user verification");

    await draft(); await review();
    const deviceInvitation = await id();
    assert.equal(await page.evaluate(() => document.activeElement.tagName), "H2");
    assert.match(await page.locator("#invitation-preview").innerText(), new RegExp(config.DeviceID));
    await page.screenshot({ path: path.join(config.Report, "desktop-invitation-review.png"), fullPage: true });
    await page.setViewportSize({ width: 360, height: 900 }); await page.emulateMedia({ colorScheme: "dark" });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    const box = await page.getByRole("button", { name: "Approve with security key", exact: true }).boundingBox(); assert.equal(box.height >= 48, true);
    await page.screenshot({ path: path.join(config.Report, "mobile-invitation-review-dark.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1050 }); await page.emulateMedia({ colorScheme: "light" });
    await approve("Invitation created"); expected.Total++; expected.Invited++; assert.deepEqual(await state(), expected);
    let secret = await page.locator("#invitation-secret").inputValue(); assert.equal(/^[A-Za-z0-9_-]{43}$/.test(secret), true);
    assert.equal(await page.locator("#invitation-secret").getAttribute("readonly"), "");
    const inventory = await page.evaluate(async () => (await fetch("/api/v1/admin/dashboard/inventory", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ Section: "enrollments", Limit: 50 }) })).text());
    assert.equal(inventory.includes(secret), false); assert.equal(inventory.includes("token_hash"), false);
    await press("Hide secret now"); assert.equal(await page.locator("#invitation-secret").count(), 0);
    const replay = await page.evaluate(async (body) => (await fetch("/api/v1/admin/invitations/confirm", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).status, lastConfirmation);
    assert.equal(replay, 403); assert.deepEqual(await state(), expected);
    checked("native approval creates one exact invitation, reveals its secret once and rejects replay; metadata remains redacted");
    checked("exact invitation review supports keyboard focus and 360px dark reflow with 48px controls");

    assert.equal(await control("PORTICO_BROWSER_INVITATION_REDEEM " + JSON.stringify({ ID: deviceInvitation, Secret: secret })), "activated");
    secret = ""; expected.Invited--; expected.Active++; assert.deepEqual(await state(), expected);
    await revokeReview(deviceInvitation); assert.match(await page.locator("#invitation-preview").innerText(), /active/);
    await approve("Enrollment revoked"); expected.Active--; expected.Revoked++; assert.deepEqual(await state(), expected);
    assert.equal(await control("PORTICO_BROWSER_INVITATION_REVOKED"), "authority_removed");
    assert.equal(await page.locator("#invitation-secret").count(), 0);
    checked("actual approved token enrolls and activates a TLS device; browser revocation closes controller authority and queues cancellation");

    await draft("connector"); await review(); const connectorInvitation = await id(); await approve("Invitation created");
    expected.Total++; expected.Invited++; assert.deepEqual(await state(), expected);
    assert.equal(await page.locator("#invitation-secret").count(), 1);
    await navigate(); assert.equal(await page.locator("#invitation-secret").count(), 0);
    await revokeReview(connectorInvitation); await approve("Enrollment revoked"); expected.Invited--; expected.Revoked++; assert.deepEqual(await state(), expected);
    checked("connector invitation uses its bound issuer; navigation clears the secret and revocation retains the record");

    await draft(); await review(); const lostInvitation = await id();
    await page.route(confirmEndpoint, async (route) => { const response = await route.fetch(); assert.equal(response.status(), 200); await route.abort("failed"); });
    const beforeLost = confirms; await press("Approve with security key"); await error();
    assert.match(await page.locator("#feedback").innerText(), /may have been applied/); assert.equal(confirms, beforeLost + 1); assert.equal(await page.locator("#invitation-secret").count(), 0);
    expected.Total++; expected.Invited++; assert.deepEqual(await state(), expected); await page.unroute(confirmEndpoint);
    await revokeReview(lostInvitation); await approve("Enrollment revoked"); expected.Invited--; expected.Revoked++; assert.deepEqual(await state(), expected);
    checked("lost secret response is never retried and its committed invitation can be revoked by identifier");

    await draft(); await review(); assert.equal(await control("PORTICO_BROWSER_REVOKE"), "revoked");
    await press("Approve with security key"); await error(); assert.deepEqual(await state(), expected); assert.equal(await page.locator("#invitation-secret").count(), 0);
    checked("live administrator revocation blocks a previously reviewed invitation");
    assert.deepEqual(errors, []); assert.equal(requests.every((url) => url.startsWith(config.Origin + "/")), true);
    assert.equal((await context.cookies()).length, 0);
    const storage = await page.evaluate(async () => ({ local: localStorage.length, session: sessionStorage.length, databases: (await indexedDB.databases()).length, caches: (await caches.keys()).length }));
    assert.deepEqual(storage, { local: 0, session: 0, databases: 0, caches: 0 });
    checked("no secret screenshots, persistent browser storage, cookies, external page requests or script errors");
    const result = { browser: browser.version(), playwright: require("playwright/package.json").version, checks, assertions, final_state: await state(), limitations: ["Virtual USB key and ephemeral TLS proxy do not qualify physical custody or native administrator delivery.", "Redemption uses the real controller and an in-process restricted fixture issuer; no hosted issuer or destination socket qualification is claimed.", "Manual hiding and navigation are qualified; the full sixty-second display timeout is not separately timed by this run."] };
    await fs.writeFile(path.join(config.Report, "result.json"), JSON.stringify(result, null, 2) + "\n");
    process.stdout.write("PORTICO_DASHBOARD_BROWSER_PASS\n");
  } finally { await browser.close(); }
})().then(() => process.exit(0), (error) => { process.stderr.write(String(error.stack || error) + "\n"); process.exit(1); });
