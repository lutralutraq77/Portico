# Locked Linux agent and user service

The development daemon starts locked and accepts explicit control requests over the existing [protected Unix socket](local-ipc.md):

```text
portico agent daemon --config /private/client.json --socket /private/runtime/agent.sock
portico agent status --socket /private/runtime/agent.sock
portico agent unlock --socket /private/runtime/agent.sock --prompt
portico agent lock --socket /private/runtime/agent.sock
```

Unlock also accepts the existing dedicated `--secrets-fd 3` input. It never reads application stdin, takes a password from arguments/environment, or falls back between secret sources. The daemon checks the public version-2 configuration shape at startup, then fully revalidates configuration, trust and encrypted identity on every explicit unlock. It performs no decryption or infrastructure access at startup. The unlock request contains a bounded UTF-8 passphrase, not a configuration path or private key. Temporary request byte buffers are cleared after their synchronous use; this does not guarantee erasure of every Go heap/string copy. Both socket peers' kernel UIDs are verified before RPC use. Other processes under the same UID and host root remain trusted.

## Lock state and concurrency

Status returns only versioned JSON with `locked`, `unlocking`, `unlocked` or `draining`. There is one unlock attempt at a time and at least one second between attempts. A successful unlock retains the identity for at most fifteen minutes including suspend. The unlock operation has a ninety-second context and boot-clock bound, with the production scrypt work factor unchanged. Missing/decreasing boot-clock readings permanently invalidate this daemon instance, including while locked; restarting starts locked again.

Lock removes the active identity from admission before canceling its operations. It waits for old backend calls to exit, and a new unlock cannot overlap their drain. Lock also cancels any pending unlock, which can never subsequently publish its result. Scrypt computation already in progress may finish before its worker can join; a five-second Lock request can therefore return failure while cancellation/drain continues. A subsequent status/lock request observes or joins that state. No automatic retry decrypts a key or reopens a session.

The daemon admits at most six resource streams within the shared eight-connection/operation cap, leaving two slots for normal control requests. Same-user denial of service is outside that boundary. The [resource protocol](agent-resource-streams.md), exact selection, live controller authorization/revocation and final acknowledgement rules are unchanged. Lock/expiry cancels the backend contexts; already delivered application bytes cannot be recalled. Shutdown joins handlers, stream workers and any pending loader work.

## Development package unit

The package adds an inactive `portico-agent.service` in the systemd user-unit directory. Its command starts the locked daemon with `%h/.config/portico/client.json` and `%t/portico-agent/agent.sock`. The unit uses a mode-0700 runtime directory and mode-0077 creation mask. Its runtime directory contains no encrypted identity/configuration state. Systemd owns that runtime directory's lifecycle, while the daemon's ordinary socket cleanup still preserves replaced entries. This follows systemd's documented [runtime-directory and execution settings](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.exec.xml).

The unit contains no password, credential file or automatic unlock. It disables privilege gain/core dumps, restricts socket families, and specifies descriptor/task/memory limits. Its 100-second stop interval accommodates the bounded-cost unlock worker before forced process termination. Restart after failure returns to the locked state. Installation does not enable or start it, provision identity files or alter host networking. Package removal removes the unit/binary and leaves separate user state untouched.

Actual user-manager execution and its limits still require systemd guest qualification. Package checks verify installed unit bytes/ownership/mode and use `systemd-analyze --user verify`; those checks do not by themselves prove live service lifecycle or sandbox enforcement.

## Evidence

Native lock-state race tests passed in 13.223 seconds: explicit-only unlock, no reuse after lock, one KDF attempt, pending-unlock cancellation, joining old key users, suspend-aware expiry and sticky clock failure. The log is `work/reports/agent-session-state.log`, SHA-256 `8a4df3ed84f6f0fd0a2aebf0f9c179f5f258545d89d619e95fa6cee473a72985`.

The later native agent/client/CLI race run also passed after the final session-validity checks and CLI rejection cases: agent 21.521 seconds, client cached, CLI 23.666 seconds. Its log is `work/reports/agent-daemon-native-checks.log`, SHA-256 `35183f2568e11990a4864f0fcfe04d94a13ce5d882608e220973dbe513980dc5`.

The initial focused NIC-less Linux daemon suite passed 22 top-level checks and 101 subcases without failures/skips. It exercised generated control/resource RPCs, six live streams plus control access, clock expiry, the actual status/lock commands and two real daemon starts/shutdowns that each remained locked. Its log is `work/reports/phase-6-agent-daemon/runtime.log`, SHA-256 `34e66040573eb3954878158224120ddb2e63d79afd92cee1af750558035a2136`; initramfs SHA-256 `4bbf54f12b5daad9e3ffee043326a92fece73dfbf96d5018bcde7a9f4a4fc95c`. It predates the additional final session-validity checks, six new CLI rejection cases and invalid-control state-preservation check.

The actual enrolled-identity daemon integration passed one top-level test and sixteen subcases without failures/skips in 392.45 seconds. It observed locked startup with zero resource authority, explicit unlock, exact catalog/selection, application bytes, manual lock during a live transfer, one destination closure/receipt, denial while locked, explicit re-unlock, a second transfer, enrollment revocation with two total closures/receipts, subsequent denial, SIGTERM and socket cleanup. Original encrypted state and signing counts remained unchanged. The production KDF cost was retained. The log is `work/reports/phase-6-daemon-resource-integration/runtime.log`, SHA-256 `39abee86a220b04de2c4c1354f07b69582b742cc63a20c9b35738e2b99a29955`; initramfs SHA-256 `b49d2e9d86db074b61d1f6694bf2c31529417fd2a024625c984f8828f8268cc8`. This binary predates the additional wrong-password daemon-unlock subcase, which still needs final-source execution. Its measured 890.904855-millisecond pairing gap does not establish the cause of the earlier intermittent direct-client EOF.

Final Linux staticcheck/vet and whitespace checks passed after correcting a test-only SA4000 finding by recording the two stateful unlock results separately. Final-source hosted checks and the new unit's package/systemd qualification remain pending.

This extends Phase 6 software. It does not resolve platform key custody, browser-origin/application isolation, physical suspend, hardware administration or the remaining [delivery gates](delivery-status.md).
