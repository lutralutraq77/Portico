"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { app } = require("electron");
const { Channel } = require("../desktop/admin/channel.cjs");
const { createWindow } = require("../desktop/admin/shell.cjs");

const channel = new Channel(), report = process.env.PORTICO_NATIVE_STATE;
app.on("window-all-closed", () => {});
const checks = [];
let win;
(async () => {
  win = await createWindow(channel, { show: false });
  const hello = await channel.ready;
  const evaluate = (source) => win.webContents.executeJavaScript(source, true);
  win.webContents.setBackgroundThrottling(false);
  const wait = async (source) => {
    const deadline = Date.now() + 8000;
    while (!(await evaluate(source))) {
      if (Date.now() >= deadline) throw new Error("Renewal UI did not converge: " + await evaluate('document.querySelector("#feedback").textContent'));
      await new Promise((resolve) => setTimeout(resolve, 40));
    }
  };
  const ready = async () => {
    await wait('document.querySelector(".inventory")?.getAttribute("aria-busy") === "false"');
    assert.equal(await evaluate('document.querySelector("#feedback").dataset.error'), "false", await evaluate('document.querySelector("#feedback").textContent'));
  };
  const press = async (name) => {
    await evaluate(`(() => { const button = [...document.querySelectorAll("button")].find((node) => (node.getAttribute("aria-label") || node.textContent).trim() === ${JSON.stringify(name)}); if (!button || button.disabled) throw new Error("Renewal button unavailable"); button.click(); })()`);
  };
  const title = async (name) => {
    await wait(`document.querySelector("#feedback").dataset.error === "true" || [...document.querySelectorAll("h2")].some((node) => node.textContent === ${JSON.stringify(name)})`);
    await ready();
  };
  const capture = async (name) => {
    await evaluate('document.fonts.ready.then(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))))');
    const picture = await win.webContents.capturePage(undefined, { stayHidden: true });
    assert.equal(picture.isEmpty(), false);
    await fs.writeFile(path.join(report, name), picture.toPNG());
  };
  await ready();
  assert.equal(await evaluate("location.origin"), hello.Origin);
  assert.equal(await evaluate("isSecureContext"), true);
  assert.deepEqual(await evaluate('({require: typeof require, process: typeof process, ipc: typeof ipcRenderer})'), { require: "undefined", process: "undefined", ipc: "undefined" });
  assert.deepEqual(Object.keys(hello).sort(), ["Origin", "StateDirectory", "Version"]);
  checks.push("actual sandboxed native window at the fixed secure origin; greeting and renderer expose no signer");

  win.webContents.debugger.attach("1.3");
  const cdp = (method, params = {}) => win.webContents.debugger.sendCommand(method, params);
  await cdp("WebAuthn.enable");
  // Observe real browser calls without changing their arguments or results.
  // A virtual authenticator may emit more than one CDP assertion event while
  // processing a request with multiple allowed credentials.
  await evaluate('(() => { const realGet=navigator.credentials.get.bind(navigator.credentials); let calls=0; navigator.credentials.get=(...args)=>{calls++;return realGet(...args);}; Object.defineProperty(window,"observedNativeGetCount",{value:()=>calls}); })()');
  let creations = 0, assertions = 0;
  win.webContents.debugger.on("message", (_event, method) => { if (method === "WebAuthn.credentialAdded") creations++; if (method === "WebAuthn.credentialAsserted") assertions++; });
  const authenticator = async () => (await cdp("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "usb", hasUserVerification: true, automaticPresenceSimulation: true, isUserVerified: true, defaultBackupEligibility: false, defaultBackupState: false } })).authenticatorId;
  let key = await authenticator();
  await evaluate('location.hash = "factors"'); await ready();
  for (let index = 0; index < 2; index++) {
    if (index) { await cdp("WebAuthn.removeVirtualAuthenticator", { authenticatorId: key }); key = await authenticator(); }
    await press("Initial key registration"); await press("Register initial key"); await title("Security key registered");
    await press("Return to security keys"); await ready();
    const id = await evaluate('(() => { const row = [...document.querySelectorAll("tbody tr")].find((node) => node.textContent.includes("Needs key test")); return row?.querySelector(\'td[data-label="Key record"]\')?.textContent; })()');
    assert.match(id, /^[0-9a-f-]{36}$/);
    await press(`Test key ${id}`); await press("Test this key"); await title("Security key test passed");
    await press("Return to security keys"); await ready();
  }
  assert.equal(creations, 2); assert.equal(assertions, 2);
  checks.push("two distinct virtual keys register with actual attestation and each passes its separate key test");

  for (const endpoint of ["/api/v1/admin/renewal/challenge", "/api/v1/admin/renewal/confirm", "/api/v1/admin/renewal/certificate", "/api/v1/admin/renewal/activate"]) {
    const outcome = await evaluate(`fetch(${JSON.stringify(endpoint)}, {method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).then((response) => response.status, () => 0)`);
    assert.notEqual(outcome, 200);
  }
  const override = await evaluate('fetch("/api/v1/admin/native-renewal/start", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({Version:1,CSR:"AA==",NotAfter:new Date(Date.now()+7200000).toISOString(),PolicyRevision:1})}).then((response)=>response.status,()=>0)');
  assert.notEqual(override, 200);
  checks.push("renderer cannot directly call issuance/activation or supply its own CSR");

  await evaluate('location.hash = "renewal"'); await title("Renew this administrator identity");
  const start = async () => {
    await evaluate('(async () => { const response=await fetch("/api/v1/admin/native-renewal/status",{method:"POST",headers:{"Content-Type":"application/json"},body:"{\\"Version\\":1}"}); const state=await response.json(); const date=new Date(Date.parse(state.CurrentNotAfter)+30*60*1000); const value=new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16); const input=document.querySelector("#renewal-not-after"); input.value=value; input.dispatchEvent(new Event("input",{bubbles:true})); })()');
    await press("Review renewal"); await title("Review administrator renewal");
  };
  await start();
  assert.equal(assertions, 2);
  await press("Cancel renewal review"); await title("Renew this administrator identity");
  assert.equal(assertions, 2);
  checks.push("review and cancellation do not submit hardware proof or issue a certificate");
  await start();
  await evaluate('document.querySelector("#renewal-panel").scrollIntoView({block:"start"})');
  await capture("native-renewal-desktop.png");
  win.setSize(360, 900); await wait("innerWidth <= 360");
  await evaluate('document.querySelector("#renewal-panel").scrollIntoView({block:"start"})');
  await capture("native-renewal-mobile.png");
  const layout = await evaluate('({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,overflow:[...document.querySelectorAll("body *")].filter((node)=>{const box=node.getBoundingClientRect();return box.width>0&&box.right>innerWidth;}).map((node)=>({tag:node.tagName,id:node.id,classes:node.className,right:node.getBoundingClientRect().right,width:node.getBoundingClientRect().width})).slice(0,24)})');
  await fs.writeFile(path.join(report, "native-renewal-mobile-layout.json"), JSON.stringify(layout, null, 2) + "\n");
  assert.ok(layout.scrollWidth <= layout.width, "Mobile renewal overflow: " + JSON.stringify(layout));
  win.setSize(1200, 900);
  checks.push("desktop and 360-pixel review show exact current/request fingerprints, expiry, policy revision and explicit approval");
  await press("Approve renewal with security key"); await title("Administrator identity renewed");
  assert.equal(await evaluate("observedNativeGetCount()"), 3);
  assert.ok(assertions >= 3);
  assert.equal(await evaluate('document.querySelector("#renewal-panel").textContent.includes("Close this window and reopen Portico")'), true);
  assert.deepEqual(await evaluate('({local:localStorage.length,session:sessionStorage.length})'), { local: 0, session: 0 });
  assert.deepEqual(await win.webContents.session.cookies.get({}), []);
  checks.push("backup key supplies one fresh assertion; native code retains and activates the issued certificate and requests a new window");
  checks.push("no cookies or browser storage retain administrator credentials");
  await fs.writeFile(path.join(report, "result.json"), JSON.stringify({ electron: process.versions.electron, chromium: process.versions.chrome, checks, creations, assertions, browserGetCalls: await evaluate("observedNativeGetCount()"), limitations: ["Both security keys are virtual; no physical custody claim.", "This portable test uses a memory journal and local issuer signer. Linux disk durability and restricted real issuer integration are separately qualified."] }, null, 2) + "\n");
  await channel.close(); app.exit(0);
})().catch(async (error) => {
  await fs.mkdir(report, { recursive: true });
  await fs.writeFile(path.join(report, "failure.json"), JSON.stringify({ message: error.message, stack: error.stack, checks }, null, 2) + "\n");
  channel.fail(); await channel.terminated; app.exit(1);
});
