"use strict";

const { app } = require("electron");
const fs = require("node:fs/promises");
const path = require("node:path");
const { Channel } = require("../desktop/admin/channel.cjs");
const { createWindow } = require("../desktop/admin/shell.cjs");

const channel = new Channel();
(async () => {
  await createWindow(channel, { show: false });
  await fs.writeFile(path.join(process.env.PORTICO_NATIVE_STATE, "intentional-failure.txt"), "intentional native failure\n");
  // Exercise the same abrupt channel failure used by protocol/renderer errors,
  // with an inherited read still pending and real Chromium children running.
  channel.fail();
  await channel.terminated;
  app.exit(1);
})().catch(async () => { channel.fail(); await channel.terminated; app.exit(2); });
