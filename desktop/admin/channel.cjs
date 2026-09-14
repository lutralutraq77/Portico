"use strict";

const { EventEmitter } = require("node:events");
const { createWriteStream } = require("node:fs");
const { Socket } = require("node:net");
const MAX_BODY = 65536, MAX_RESPONSE = 262144, MAX_HEADER = 4096;

// Electron replaces process.stdin with an immediate EOF on Windows. Read the
// inherited handle itself; this is still the parent's anonymous pipe, never a
// file path or a listener. Linux uses its ordinary pollable stdin stream.
function inheritedInput() {
  return process.platform === "win32" ? new Socket({ fd: 0, readable: true, writable: false }) : process.stdin;
}

// Only the main process sees this anonymous pipe. There is no renderer IPC,
// HTTP listener, private-key import, arbitrary signer or external proxy API.
class Channel extends EventEmitter {
  constructor(input = inheritedInput(), output = createWriteStream(null, { fd: 1, autoClose: true })) {
    super();
    this.input = input; this.output = output; this.buffer = Buffer.alloc(0);
    this.pending = new Map(); this.nextID = 0; this.closed = false; this.hello = false;
    this.terminated = new Promise((resolve) => output.once("close", resolve));
    this.ready = new Promise((resolve, reject) => { this.resolveReady = resolve; this.rejectReady = reject; });
    input.on("data", (part) => {
      if (this.closed) return;
      if (this.buffer.length + part.length > 4 * (MAX_RESPONSE + MAX_HEADER + 4)) return this.fail();
      this.buffer = Buffer.concat([this.buffer, part]);
      try { this.consume(); } catch { this.fail(); }
    });
    input.on("end", () => this.fail()); input.on("error", () => this.fail());
    output.on("error", () => this.fail());
  }
  consume() {
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (length < 1 || length > MAX_HEADER) throw new Error("Invalid native header");
      if (this.buffer.length < 4 + length) return;
      const header = JSON.parse(this.buffer.subarray(4, 4 + length).toString("utf8"));
      if (header.Version !== 1) throw new Error("Invalid native version");
      if (!this.hello) {
        if (typeof header.Origin !== "string" || typeof header.StateDirectory !== "string" || Object.keys(header).sort().join() !== "Origin,StateDirectory,Version") throw new Error("Invalid native configuration");
        this.buffer = this.buffer.subarray(4 + length); this.hello = true; this.resolveReady(header); continue;
      }
      if (!Number.isSafeInteger(header.ID) || !this.pending.has(header.ID) || !Number.isSafeInteger(header.Length) || header.Length < 0 || header.Length > MAX_RESPONSE || !Number.isInteger(header.Status) || typeof header.Failed !== "boolean") throw new Error("Invalid native response");
      if (this.buffer.length < 4 + length + header.Length) return;
      const body = Buffer.from(this.buffer.subarray(4 + length, 4 + length + header.Length));
      this.buffer = this.buffer.subarray(4 + length + header.Length);
      const waiting = this.pending.get(header.ID);
      if (Object.keys(header).sort().join() !== "Failed,Headers,ID,Length,Status,Version" || header.ID !== this.pending.keys().next().value) throw new Error("Invalid native response fields");
      if (header.Failed) {
        if (header.Status !== 0 || header.Length !== 0 || header.Headers !== null || waiting.close) throw new Error("Invalid native failure");
      } else if (!waiting.close) {
        if (![200, 403].includes(header.Status) || !header.Headers || Array.isArray(header.Headers) || typeof header.Headers !== "object" || Object.values(header.Headers).some((value) => typeof value !== "string")) throw new Error("Invalid native result");
      }
      if (waiting.close) {
        if (header.Failed || header.Status !== 204 || header.Length !== 0 || header.Headers !== null) throw new Error("Invalid native close");
        this.closed = true; this.input.destroy(); this.output.end();
      }
      this.pending.delete(header.ID);
      if (header.Failed) { body.fill(0); waiting.reject(new Error("Native request failed")); }
      else waiting.resolve({ status: header.Status, headers: header.Headers, body });
    }
  }
  exchange(fields, body = Buffer.alloc(0)) {
    if (this.closed || !this.hello || this.pending.size >= 4 || this.nextID >= 4096 || !Buffer.isBuffer(body) || body.length > MAX_BODY) return Promise.reject(new Error("Native channel unavailable"));
    if (!fields || typeof fields !== "object" || Object.keys(fields).some((key) => !["Method", "Path", "Origin", "Site", "Close"].includes(key))) return Promise.reject(new Error("Native request fields rejected"));
    const ID = ++this.nextID;
    const header = Buffer.from(JSON.stringify({ Version: 1, ID, Method: "", Path: "", Origin: "", Site: "", Close: false, ...fields, Length: body.length }));
    if (header.length > MAX_HEADER) return Promise.reject(new Error("Native request too large"));
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(header.length);
    return new Promise((resolve, reject) => {
      this.pending.set(ID, { resolve, reject, close: fields.Close === true });
      // One write keeps concurrent frame headers and bodies together. Four
      // outstanding requests cap this process's queue even under backpressure.
      this.output.write(Buffer.concat([prefix, header, body]), (error) => { if (error) this.fail(); });
    });
  }
  async close() {
    if (this.closed) return this.terminated;
    if (this.pending.size) { this.fail(); return this.terminated; }
    const response = await this.exchange({ Close: true });
    if (response.status !== 204 || response.body.length !== 0) throw new Error("Invalid native close");
    await this.terminated;
  }
  fail() {
    if (this.closed) return;
    this.closed = true; this.buffer.fill(0); this.buffer = Buffer.alloc(0);
    this.rejectReady(new Error("Native channel closed"));
    for (const waiting of this.pending.values()) waiting.reject(new Error("Native request outcome unavailable"));
    this.pending.clear(); this.output.destroy(); this.input.destroy();
    void this.terminated.then(() => this.emit("closed"));
  }
}

module.exports = { Channel, MAX_BODY };
