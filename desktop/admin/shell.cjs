"use strict";

const { app, BrowserWindow, Menu, session } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { MAX_BODY } = require("./channel.cjs");

const state = process.env.PORTICO_NATIVE_STATE;
if (process.versions.electron !== "44.3.0" || !state || !path.isAbsolute(state)) throw new Error("Native runtime configuration rejected");
for (const flag of ["no-sandbox", "disable-web-security", "remote-debugging-port", "remote-debugging-pipe", "inspect", "inspect-brk"]) {
  if (app.commandLine.hasSwitch(flag)) throw new Error("Unsafe native launch");
}
const stateDirectory = path.resolve(state);
fs.mkdirSync(stateDirectory, { recursive: true, mode: 0o700 });
app.setPath("userData", stateDirectory);
app.setPath("sessionData", path.join(stateDirectory, "session"));
app.setPath("crashDumps", path.join(stateDirectory, "crashes"));
app.setAppLogsPath(path.join(stateDirectory, "logs"));
app.enableSandbox();
app.commandLine.appendSwitch("disable-background-networking");
app.commandLine.appendSwitch("disable-http-cache");

const getPaths = new Set(["/admin", "/admin.js", "/admin.css"]);
const postPaths = new Set(["/api/v1/admin/dashboard/inventory", "/api/v1/admin/dashboard/access", "/api/v1/admin/factors/challenge", "/api/v1/admin/factors/confirm", "/api/v1/admin/invitations/challenge", "/api/v1/admin/invitations/confirm", "/api/v1/admin/policy/preview", "/api/v1/admin/policy/challenge", "/api/v1/admin/policy/confirm"]);

async function boundedBody(request) {
  if (!request.body) return Buffer.alloc(0);
  const reader = request.body.getReader(), chunks = [];
  let length = 0;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) return Buffer.concat(chunks, length);
      length += result.value.length;
      if (length > MAX_BODY) { await reader.cancel(); throw new Error("Native body too large"); }
      chunks.push(Buffer.from(result.value));
    }
  } finally { reader.releaseLock(); }
}

async function createWindow(channel, { show = true } = {}) {
  const hello = await channel.ready;
  const origin = hello.Origin, parsed = new URL(origin);
  if (parsed.protocol !== "https:" || parsed.origin !== origin || parsed.pathname !== "/" || parsed.search || parsed.hash || path.resolve(hello.StateDirectory) !== stateDirectory) throw new Error("Native origin rejected");
  const permitted = (value, method) => {
    try {
      const url = new URL(value);
      return url.origin === origin && !url.search && !url.username && !url.password && (method === "GET" ? getPaths : method === "POST" ? postPaths : new Set()).has(url.pathname);
    } catch { return false; }
  };
  await app.whenReady(); Menu.setApplicationMenu(null);
  const ses = session.fromPartition("portico-admin-" + crypto.randomUUID(), { cache: false });
  let contents;
  ses.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);
  ses.setDevicePermissionHandler(() => false);
  ses.on("will-download", (event) => event.preventDefault());
  ses.webRequest.onBeforeRequest((details, callback) => {
    const ownFrame = contents && !contents.isDestroyed() && details.webContentsId === contents.id && details.frame === contents.mainFrame;
    let currentOrigin = false;
    try { currentOrigin = new URL(details.frame.url).origin === origin; } catch { /* No established administration document. */ }
    callback({ cancel: !ownFrame || !permitted(details.url, details.method) || (details.method === "POST" && !currentOrigin) });
  });
  ses.protocol.handle("https", async (request) => {
    let body;
    try {
      if (!permitted(request.url, request.method)) throw new Error("Native target rejected");
      const url = new URL(request.url), originHeader = request.headers.get("origin") || "", site = request.headers.get("sec-fetch-site") || "";
      if ((originHeader && originHeader !== origin) || (request.method === "POST" && request.headers.get("content-type") !== "application/json") || (site && site !== "none" && site !== "same-origin") || request.headers.has("authorization") || request.headers.has("cookie") || request.headers.has("range")) throw new Error("Native browser request rejected");
      body = await boundedBody(request);
      if (request.method === "GET" && body.length) throw new Error("Unexpected native body");
      // Electron's intercepted HTTPS Request omits Chromium's Origin and Fetch
      // Metadata. The isolated session admits only this window's main frame.
      // Supply its fixed origin to Go; any conflicting supplied value is denied.
      const result = await channel.exchange({ Method: request.method, Path: url.pathname, Origin: request.method === "POST" ? origin : originHeader, Site: "same-origin" }, body);
      if (result.status !== 200 && result.status !== 403) throw new Error("Native status rejected");
      return new Response(result.body, { status: result.status, headers: result.headers });
    } catch {
      return new Response('{"error":"request rejected"}', { status: 502, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff" } });
    } finally { if (body) body.fill(0); }
  });
  const win = new BrowserWindow({ show: false, width: 1200, height: 900, minWidth: 360, minHeight: 600, title: "Portico — Private administration", webPreferences: { session: ses, nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true, allowRunningInsecureContent: false, webviewTag: false, devTools: false, navigateOnDragDrop: false } });
  contents = win.webContents;
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  const navigation = (event, destination) => { if (!permitted(destination, "GET") || new URL(destination).pathname !== "/admin") event.preventDefault(); };
  win.webContents.on("will-navigate", navigation);
  win.webContents.on("will-redirect", (event) => event.preventDefault());
  win.webContents.on("will-attach-webview", (event) => event.preventDefault());
  win.webContents.setWebRTCIPHandlingPolicy("disable_non_proxied_udp");
  channel.on("closed", () => { if (!win.isDestroyed()) win.destroy(); });
  await win.loadURL(origin + "/admin");
  if (show) win.show();
  return win;
}

module.exports = { createWindow };
