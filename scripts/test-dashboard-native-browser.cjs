"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { app, session } = require("electron");
const { Channel } = require("../desktop/admin/channel.cjs");
const { createWindow } = require("../desktop/admin/shell.cjs");

const channel = new Channel(), report = process.env.PORTICO_NATIVE_STATE;
const checks = [], checked = (value) => checks.push(value);
const requestMetadata = [];
// Main-process test observation only: record bounded booleans and status, never
// bodies, credential values, proof bytes or arbitrary header values.
const fromPartition = session.fromPartition.bind(session);
session.fromPartition = (...args) => {
  const ses = fromPartition(...args), handle = ses.protocol.handle.bind(ses.protocol);
  ses.protocol.handle = (scheme, handler) => handle(scheme, async (request) => {
    const response = await handler(request);
    if (requestMetadata.length < 100) requestMetadata.push({ method: request.method, path: new URL(request.url).pathname, hasOrigin: request.headers.has("origin"), sameOrigin: request.headers.get("origin") === new URL(request.url).origin, json: request.headers.get("content-type") === "application/json", site: request.headers.get("sec-fetch-site"), status: response.status });
    return response;
  });
  return ses;
};
let win;

(async () => {
  win = await createWindow(channel, { show: false });
  const hello = await channel.ready;
  assert.deepEqual(Object.keys(hello).sort(), ["Origin", "StateDirectory", "Version"]);
  const evaluate = (source) => win.webContents.executeJavaScript(source, true);
  win.webContents.setBackgroundThrottling(false);
  const capture = async (name) => {
    await evaluate('document.fonts.ready.then(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))))');
    const picture = await win.webContents.capturePage(undefined, { stayHidden: true });
    assert.equal(picture.isEmpty(), false);
    await fs.writeFile(path.join(report, name), picture.toPNG());
  };
  const wait = async (source) => {
    const until = Date.now() + 8000;
    while (!(await evaluate(source))) {
      if (Date.now() >= until) throw new Error("Native UI condition did not converge");
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
  };
  const ready = async () => {
    await wait('document.querySelector(".inventory")?.getAttribute("aria-busy") === "false"');
    assert.equal(await evaluate('document.querySelector("#feedback").dataset.error'), "false", await evaluate('document.querySelector("#feedback").textContent'));
  };
  const press = async (name) => {
    await evaluate(`(() => { const button = [...document.querySelectorAll("button")].find((node) => (node.getAttribute("aria-label") || node.textContent).trim() === ${JSON.stringify(name)}); if (!button || button.disabled) throw new Error("Native button unavailable"); button.click(); })()`);
  };
  const success = async (title) => {
    await wait(`document.querySelector("#feedback").dataset.error === "true" || [...document.querySelectorAll("h2")].some((node) => node.textContent === ${JSON.stringify(title)})`);
    assert.equal(await evaluate('document.querySelector("#feedback").dataset.error'), "false", await evaluate('document.querySelector("#feedback").textContent'));
  };
  await ready();
  assert.equal(await evaluate("location.origin"), hello.Origin);
  assert.equal(await evaluate("isSecureContext"), true);
  assert.deepEqual(await evaluate('({require: typeof require, process: typeof process, ipc: typeof ipcRenderer})'), { require: "undefined", process: "undefined", ipc: "undefined" });
  const preferences = win.webContents.getLastWebPreferences();
  assert.equal(preferences.sandbox, true); assert.equal(preferences.contextIsolation, true); assert.equal(preferences.nodeIntegration, false); assert.equal(preferences.webSecurity, true); assert.equal(preferences.webviewTag, false);
  checked("real dashboard renders at the stable secure origin with sandbox, isolation and no renderer Node or IPC");
  checked("native greeting contains no device key or certificate export");

  // These actual renderer requests must be denied before native network use.
  for (const target of ["https://unrelated.portico.test/admin", "http://127.0.0.1:9/admin", hello.Origin + "/api/v1/device/catalog", hello.Origin + "/admin?override=1"]) {
    const outcome = await evaluate(`fetch(${JSON.stringify(target)}).then((r) => r.status, () => 0)`);
    assert.notEqual(outcome, 200);
  }
  const beforeURL = win.webContents.getURL();
  await evaluate('window.open("https://unrelated.portico.test/admin")');
  assert.equal(require("electron").BrowserWindow.getAllWindows().length, 1);
  assert.equal(win.webContents.getURL(), beforeURL);
  checked("foreign origin, HTTP, unknown path, query override and popup requests are denied");
  const second = new (require("electron").BrowserWindow)({ show: false, webPreferences: { session: win.webContents.session, sandbox: true, contextIsolation: true, nodeIntegration: false } });
  try {
    await assert.rejects(second.loadURL(hello.Origin + "/admin"));
  } finally { second.destroy(); }
  const background = await win.webContents.session.fetch(hello.Origin + "/admin").then((r) => r.status, () => 0);
  assert.notEqual(background, 200);
  checked("another window and a request without the owning frame cannot use the administrator session");

  win.webContents.debugger.attach("1.3");
  const cdp = (method, params = {}) => win.webContents.debugger.sendCommand(method, params);
  await cdp("WebAuthn.enable");
  let creations = 0, assertions = 0;
  win.webContents.debugger.on("message", (_event, method) => { if (method === "WebAuthn.credentialAdded") creations++; if (method === "WebAuthn.credentialAsserted") assertions++; });
  const authenticator = async () => (await cdp("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "usb", hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true, defaultBackupEligibility: false, defaultBackupState: false } })).authenticatorId;
  let key = await authenticator();
  await evaluate('location.hash = "factors"'); await ready();
  const ids = [];
  for (let index = 0; index < 2; index++) {
    if (index) { await cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: key }); key = await authenticator(); }
    await press("Initial key registration");
    if (!index) {
      await capture("native-desktop-key-review.png");
      win.setSize(360, 900); await wait("innerWidth <= 360");
      assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth"), true);
      await evaluate('[...document.querySelectorAll("h2")].find((node) => node.textContent === "Initial key registration").scrollIntoView({ block: "start" })');
      await capture("native-mobile-key-review.png");
      win.setSize(1200, 900);
    }
    await press("Register initial key"); await success("Security key registered");
    await press("Return to security keys"); await ready();
    const id = await evaluate('(() => { const row = [...document.querySelectorAll("tbody tr")].find((node) => node.textContent.includes("Needs key test")); return row?.querySelector(\'td[data-label="Key record"]\')?.textContent; })()');
    assert.match(id, /^[0-9a-f-]{36}$/); ids.push(id);
    await press(`Test key ${id}`); await press("Test this key"); await success("Security key test passed");
    await press("Return to security keys"); await ready();
    checked(`native shell key ${index + 1} registers with attestation then passes its separate exact-key test`);
  }
  assert.notEqual(ids[0], ids[1]); assert.equal(creations, 2); assert.equal(assertions, 2);
  await press(`Retire key ${ids[0]}`); await press("Approve retirement with backup key"); await success("Security key retired");
  await press("Return to security keys"); await ready(); assert.equal(assertions, 3);
  checked("new backup performs native hardware approval to retire the primary through the real controller");
  await press("Initial key registration"); await press("Register initial key"); await wait('document.querySelector("#feedback").dataset.error === "true"');
  assert.equal(creations, 2);
  checked("retirement does not reopen the first-two-key bootstrap allowance");
  assert.deepEqual(await evaluate('({local:localStorage.length,session:sessionStorage.length})'), { local: 0, session: 0 });
  assert.deepEqual(await win.webContents.session.cookies.get({}), []);
  checked("native shell leaves no cookies or browser storage");
  await fs.writeFile(path.join(report, "result.json"), JSON.stringify({ electron: process.versions.electron, chromium: process.versions.chrome, checks, creations, assertions, limitations: ["Windows execution qualifies the portable shell/transport components; the supported Linux package and OS key provider still need qualification.", "Administrator TLS identity is an in-memory Go fixture; both hardware factors are virtual. Complete owner bootstrap and physical recovery are not established."] }, null, 2) + "\n");
  await channel.close(); win.destroy(); app.exit(0);
})().catch(async (error) => {
  await fs.mkdir(report, { recursive: true });
  await fs.writeFile(path.join(report, "failure.json"), JSON.stringify({ message: error.message, stack: error.stack, checks, requestMetadata }, null, 2) + "\n");
  channel.fail(); await channel.terminated; app.exit(1);
});
