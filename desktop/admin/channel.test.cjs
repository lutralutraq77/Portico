"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { PassThrough, Writable } = require("node:stream");
const { Channel } = require("./channel.cjs");

function packet(header, body = Buffer.alloc(0)) {
  const data = Buffer.from(JSON.stringify(header)), prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(data.length);
  return Buffer.concat([prefix, data, body]);
}
function response(ID, body = Buffer.alloc(0), change = {}) {
  return packet({ Version: 1, ID, Status: 200, Length: body.length, Headers: { "Content-Type": "application/json" }, Failed: false, ...change }, body);
}
function setup(t) {
  const input = new PassThrough(), writes = [];
  const output = new Writable({ write(chunk, _encoding, callback) { writes.push(Buffer.from(chunk)); callback(); } });
  const channel = new Channel(input, output);
  channel.ready.catch(() => {});
  t.after(async () => { channel.fail(); await channel.terminated; });
  return { channel, input, output, writes };
}
async function ready(f) {
  f.input.write(packet({ Version: 1, Origin: "https://admin.portico.test", StateDirectory: "/private/state" }));
  assert.equal((await f.channel.ready).Origin, "https://admin.portico.test");
}

test("greeting and response survive arbitrary pipe chunk boundaries", async (t) => {
  const f = setup(t);
  for (const byte of packet({ Version: 1, Origin: "https://admin.portico.test", StateDirectory: "/private/state" })) f.input.write(Buffer.from([byte]));
  await f.channel.ready;
  const result = f.channel.exchange({ Method: "GET", Path: "/admin" });
  for (const byte of response(1, Buffer.from("private"))) f.input.write(Buffer.from([byte]));
  assert.equal((await result).body.toString(), "private");
  assert.equal(f.writes.length, 1);
});

test("four maximum responses may arrive in one coalesced read", async (t) => {
  const f = setup(t); await ready(f);
  const pending = Array.from({ length: 4 }, () => f.channel.exchange({ Method: "GET", Path: "/admin" }));
  await assert.rejects(f.channel.exchange({ Method: "GET", Path: "/admin" }));
  const body = Buffer.alloc(262144, 42);
  f.input.write(Buffer.concat([1, 2, 3, 4].map((id) => response(id, body))));
  for (const result of await Promise.all(pending)) assert.deepEqual(result.body, body);
  assert.equal(f.writes.length, 4);
});

test("a lost sensitive confirmation rejects without automatic retry", async (t) => {
  const f = setup(t); await ready(f);
  const rejected = assert.rejects(f.channel.exchange({ Method: "POST", Path: "/api/v1/admin/policy/confirm" }, Buffer.from("{}")), /outcome unavailable/);
  f.input.end(); await rejected; await f.channel.terminated;
  assert.equal(f.writes.length, 1);
  await assert.rejects(f.channel.exchange({ Method: "GET", Path: "/admin" }));
});

test("explicit request rejection does not desynchronize the next response", async (t) => {
  const f = setup(t); await ready(f);
  const rejected = assert.rejects(f.channel.exchange({ Method: "GET", Path: "/unknown" }), /request failed/);
  f.input.write(response(1, Buffer.alloc(0), { Status: 0, Headers: null, Failed: true })); await rejected;
  const next = f.channel.exchange({ Method: "GET", Path: "/admin" });
  f.input.write(response(2)); assert.equal((await next).status, 200);
});

for (const [name, change] of Object.entries({ unknownID: { ID: 8 }, version: { Version: 2 }, largeBody: { Length: 262145 }, negativeBody: { Length: -1 }, unknownField: { Sign: true }, badStatus: { Status: 302 }, falseFailure: { Failed: true }, unsolicitedClose: { Status: 204 }, invalidHeaders: { Headers: { Cookie: [] } } })) {
  test(`malformed response closes the entire channel: ${name}`, async (t) => {
    const f = setup(t); await ready(f);
    const rejected = assert.rejects(f.channel.exchange({ Method: "GET", Path: "/admin" }));
    f.input.write(response(1, Buffer.alloc(0), change)); await rejected;
    assert.equal(f.channel.closed, true); assert.equal(f.writes.length, 1);
  });
}

test("close acknowledgment and immediate pipe EOF finish cleanly", async (t) => {
  const f = setup(t); await ready(f);
  const closing = f.channel.close();
  f.input.end(response(1, Buffer.alloc(0), { Status: 204, Headers: null }));
  await closing; assert.equal(f.channel.closed, true); assert.equal(f.writes.length, 1);
});

test("request fields cannot override framing or carry an oversized body", async (t) => {
  const f = setup(t); await ready(f);
  for (const fields of [{ ID: 7 }, { Version: 2 }, { Length: -1 }, { Sign: true }]) await assert.rejects(f.channel.exchange(fields));
  await assert.rejects(f.channel.exchange({ Method: "POST" }, Buffer.alloc(65537)));
  assert.equal(f.writes.length, 0);
});
