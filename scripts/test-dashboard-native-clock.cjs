"use strict";

const { app } = require("electron");
const fs = require("node:fs/promises");
const path = require("node:path");
const { Channel } = require("../desktop/admin/channel.cjs");
const { createWindow } = require("../desktop/admin/shell.cjs");

const channel = new Channel();
channel.on("closed", async () => { await channel.terminated; app.exit(1); });
(async () => {
  const window = await createWindow(channel, { show: false });
  if (window.isDestroyed() || !window.webContents.getURL().startsWith("https://admin.portico.test:")) {
    throw new Error("native clock fixture did not load");
  }
  // The Go fixture injects loss of its private health estimate only after the
  // real window has loaded. This marker carries no identity or browser data.
  await fs.writeFile(path.join(process.env.PORTICO_NATIVE_STATE, "clock-ready.txt"), "native clock fixture ready\n");
})().catch(async () => { channel.fail(); await channel.terminated; app.exit(2); });
