# Native administration transport and window

The development administrator window connects the existing dashboard to the actual administrator TLS server through a Go-owned transport. The Go process retains the administrator `crypto.Signer`. Electron receives a public origin and state-directory greeting, then bounded HTTP responses over anonymous inherited pipes. No browser client-key import, local HTTP listener, cookie session, general signing method or arbitrary proxy target is provided.

This implements and qualifies a component of TB-06 and CTRL-20. It does not yet provide an installed administration command, platform key custody, the management-resource route, complete owner bootstrap, suspend-aware native session expiry or independent recovery. Those remain Phase 6/7 work. The canonical acceptance manifest remains seven implemented and 84 planned scenarios.

## Enforced boundaries

The native configuration fixes an HTTPS origin, trusted server root, server SPKI pin, administrator certificate profile and one literal loopback bootstrap address or protected local IPC path. The browser cannot choose the dial address. Every request opens fresh TLS 1.3, verifies the server chain, hostname and pin, and proves possession of the administrator key. The controller rechecks its live certificate registry and existing operation-specific hardware approvals. The transport neither follows redirects nor retries an uncertain confirmation.

Only the three dashboard assets and nine existing administrator POST endpoints are available. Go validates strict JSON, method, exact path, origin, response type, security headers and body limits. Admission is capped at four requests; each has a maximum five-second deadline, and the native session has a maximum ten-minute lifetime bounded by certificate expiry. This timer is not a claim of qualified Linux suspend or clock-rollback handling.

The Electron window uses a fresh in-memory session, a sandboxed renderer, context isolation and no renderer Node, preload or application IPC. Requests must belong to the owning window's main frame and fixed origin; a second window and background session requests are denied. Downloads, popups, webviews, redirects and unrelated navigation are denied. The existing dashboard CSP remains active. This is a browser request boundary, not a qualified OS egress sandbox for Chromium internals or compromised native code.

Electron's intercepted HTTPS request omits Chromium-generated Origin and Fetch Metadata headers. The native shell supplies its fixed origin only after the session's request gate identifies the owning frame; conflicting supplied values are rejected. The real browser tests exercise both permitted requests and requests from another window or without an owning frame. Go still requires the exact origin on POST, and the controller continues to require authenticated administrator TLS.

The pipe protocol has bounded JSON headers and raw bodies, consecutive request IDs, no resynchronization after malformed input and an explicit close acknowledgment. Cancellation interrupts blocked reads/writes and joins workers. On Windows, the pinned Electron runtime replaces `process.stdin` with EOF; the shell reads inherited fd 0 directly. Its output stream owns fd 1 so failure actually closes the pipe. The launcher accepts at most one observed startup CRLF on Windows; subsequent whitespace or invalid framing is rejected. Windows execution here qualifies portable components and does not advance Phase 8.

## Qualification

`internal/adminbridge` tests use actual TLS connections and a counted `crypto.Signer` to verify fresh device signatures, server pin/root/hostname/TLS-version failures, request rejection before network use, response limits, partial responses, lost confirmations without retry, bounded admission and cancellation. Pipe tests cover large assets, malformed/duplicate fields, body/header bounds, blocked I/O and exact startup framing. The Node test suite covers chunk splitting/coalescing, four maximum responses, malformed replies, shutdown and uncertain outcomes.

The opt-in `TestDashboardNativeBrowser` launches the pinned Electron executable from Go and uses the real SQLite/controller/TLS implementation. Two initially empty virtual USB authenticators register through native WebAuthn creation, pass separate exact-key assertions and allow the backup to retire the primary. The controller database and audit chain independently confirm the resulting counts. A retired record does not reopen initial enrollment. Renderer isolation, request ownership, secure origin, mobile reflow and absence of browser cookies/storage are also checked. Test-only CDP runs inside the main process; production has no debugging port or renderer test hooks.

Earlier failed attempts are retained under `E:/Portico/work/reports/dashboard-native-browser-v1` through `v6` and adjacent logs. They exposed the stdin EOF, startup framing, omitted browser headers and output-close deadlock. The subsequent native window and request-isolation runs passed; the recorded evidence identifies the tested sources and results. Screenshots are taken before key registration, never while invitation secrets are displayed.

Final local qualification (`native-admin-verified`) passed ten Go transport tests and 43 subcases under the race detector, all 15 channel tests under Electron's embedded Node runtime, and both real native-browser tests under the race detector. The functional window passed nine groups in 6.30 seconds; deliberate native failure terminated and joined in 2.24 seconds. Final desktop/mobile screenshots were visually inspected. The [source-bound evidence](phase-7-native-evidence.json) records hashes and limitations. An intermediate hidden-window capture failed, and a later run exposed delayed child/stderr shutdown despite successful UI assertions; both remain failed evidence. The launcher now owns its file descriptors, waits concurrently for child exit and channel completion, and does not leave an inherited stderr copy worker. An intermediate desktop capture was blank; only the inspected final captures provide visual evidence.

Run the portable qualification from PowerShell 7:

~~~powershell
./scripts/prepare-admin-runtime.ps1 -WorkRoot E:/Portico/work
./scripts/test-native-admin.ps1 -WorkRoot E:/Portico/work
~~~

The `Native administrator window` PR workflow runs the same test on Ubuntu with Xvfb and the verified Chromium sandbox helper. No `--no-sandbox` or global certificate-trust bypass is permitted. Hosted result and artifact verification must be recorded before claiming Linux qualification. The scripts prepare a development test runtime, not a supported user installer.

## Runtime dependency review

[Electron 44.3.0](https://github.com/electron/electron/releases/tag/v44.3.0), released 8 September 2026, supplies Chromium 152.0.7977.78, native WebAuthn and a maintained renderer sandbox. The release includes fixes to frame-associated IPC and device-permission handling relevant to this boundary. The official project supports the [latest three stable major releases](https://www.electronjs.org/docs/latest/tutorial/electron-timelines); version 44.3.0 was the latest stable release when selected. The release notes and [published advisory index](https://github.com/electron/electron/security/advisories) were reviewed on 14 September 2026. This review and the Go vulnerability scanner are not a complete vulnerability assessment of the bundled browser.

The archive digests are pinned in `desktop/admin/runtime.lock.json` from official GitHub release asset metadata. Windows and Linux archives are roughly 158 MB and 123 MB compressed respectively. They introduce Chromium, Node and their bundled libraries; there are no added npm packages. Keep the archive's MIT license and Chromium/third-party notices with any future distribution. Electron's license does not decide Portico's unresolved project license or establish compatibility of a future complete distribution.

An upgrade requires a reviewed release, fresh official archive digests, updating the version guard, rerunning native transport/channel/browser tests and preserving new evidence. Removing this component removes the desktop directory, adminbridge package and opt-in tests/workflow; the existing administrator server and dashboard do not depend on Electron. Signed Portico release/update metadata, a complete browser SBOM/security review, hardened packaged runtime fuses, protected executable/state ownership and an installed Linux key-provider/launcher remain required before a supported release.

Primary implementation references: [protocol handling](https://www.electronjs.org/docs/latest/api/protocol), [request frame metadata](https://www.electronjs.org/docs/latest/api/web-request), [Electron security guidance](https://www.electronjs.org/docs/latest/tutorial/security), [pinned Windows stdin implementation](https://github.com/electron/electron/blob/v44.3.0/lib/common/init.ts), and [console environment settings](https://www.electronjs.org/docs/latest/api/environment-variables).
