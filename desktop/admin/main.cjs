"use strict";

const { app } = require("electron");
const { Channel } = require("./channel.cjs");
const { createWindow } = require("./shell.cjs");

const channel = new Channel();
let closing = false;
app.on("window-all-closed", async () => {
  if (closing) return;
  closing = true;
  try { await channel.close(); app.exit(0); }
  catch { app.exit(1); }
});
createWindow(channel).catch(async () => { channel.fail(); await channel.terminated; app.exit(1); });
