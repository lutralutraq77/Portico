# Portico save point — 27 September 2026

This is the restart checklist for the next working session. **Phases 6 and 7 are incomplete. Finish both in full, then obtain the owner's approval before starting Phase 8.** This save point records existing work and the remaining backlog; it does not waive requirements or declare a supported release.

The preserved [master requirements](requirements/PORTICO_MASTER_PROMPT.md), [acceptance plan](ACCEPTANCE_TEST_PLAN.md), [security invariants](SECURITY_INVARIANTS.md), [delivery ledger](docs/delivery-status.md) and [open questions](OPEN_QUESTIONS.md) remain authoritative for scope. Older reports describe their recorded source, not necessarily the current implementation. Reconcile stale present-tense status wording against the evidence below before repeating it.

## 1. Exact saved state

| Item | State at this checkpoint |
|---|---|
| Latest implementation commit | `d22e2c46652daec40943ba58af7467f72c211322` — Add dedicated management relay admission |
| Working branch | `codex/phase-7-dashboard`, pushed to `origin` |
| Review | [PR #5](https://github.com/lutralutraq77/Portico/pull/5), open, draft, unmerged |
| Base branch | `codex/phase-5-connector`; last recorded implementation `33d7807b87fe9935790cc3c99bcbf7d6c2b887b9` |
| Local implementation checkout | `E:\Portico-dashboard` |
| Shared development storage | `E:\Portico\work` — tools, caches, temporary files, downloads and reports |
| Local operational history | `E:\Portico\work\RESUME.md`; historical entries are retained and can be superseded by newer entries |
| Uncommitted implementation | None when this checkpoint was started; the four pending transport files are in `d22e2c4` |
| Runtime acceptance | **7 implemented / 84 planned / 91 total**; component test counts are separate |
| Owner inputs | Primary key model, backup key model and private administrator hostname remain **undecided** |
| Write access | Restored for this session; the earlier E: sandbox blockage is historical |

This documentation commit will follow the implementation commit above. Its own SHA is available in Git history; do not confuse the saved implementation SHA with a later documentation or implementation revision.

### Verified evidence and its limits

- The fresh Windows race regression passed **20 top-level tests and 84 subcases**, with zero failures. The controller package took 68.986 seconds. The `internal/carrier` package reported no matching tests; counted tests ran in `internal/controller`.
- Command: `go test -race ./internal/carrier ./internal/controller -run '^(TestCarrier|TestRelay|TestManagement)' -count=1 -v -timeout 5m`.
- Local log: `E:\Portico\work\reports\management-carrier-push-20260927.log`; SHA-256 `744302bb02418bd8f5fcf4ffbc714758f6c034c0d8623bb019b444173f3d25ed`. This log is local, not an uploaded artifact in the repository.
- Formatting, staged whitespace and a redacted staged-diff secret scan passed before the implementation push. The secret scan covered about 12.25 KB and found no leaks.
- **All seven hosted workflows for `d22e2c4` report success**, as checked through the authenticated repository API. See the run links below and the [machine-readable checkpoint evidence](docs/savepoint-2026-09-27-evidence.json).
- Current-source job logs, tested merge/source tree equality, downloaded archives and embedded artifact hashes still need independent verification. A green workflow is not evidence that the new management path has dedicated end-to-end tests.
- Earlier source `e4b13a6` also passed seven workflows. Its native/Linux/Arch-service logs were inspected and its tested merge tree matched that source. Its downloadable artifacts were not independently verified during the read-only session. Do not describe those older results as `d22e2c4` results.

| Workflow | Saved implementation run |
|---|---|
| Repository quality | [36344560104](https://github.com/lutralutraq77/Portico/actions/runs/36344560104) |
| Isolated Linux runtime | [36344560119](https://github.com/lutralutraq77/Portico/actions/runs/36344560119) |
| Native administrator window | [36344560121](https://github.com/lutralutraq77/Portico/actions/runs/36344560121) |
| Arch user service runtime | [36344560086](https://github.com/lutralutraq77/Portico/actions/runs/36344560086) |
| Arch development package | [36344560200](https://github.com/lutralutraq77/Portico/actions/runs/36344560200) |
| CodeQL | [36344560115](https://github.com/lutralutraq77/Portico/actions/runs/36344560115) |
| Dependency review | [36344560188](https://github.com/lutralutraq77/Portico/actions/runs/36344560188) |

## 2. What already exists

Use these components rather than starting them again. Implementation and recorded component qualification do not close all platform or physical gates.

| Area | Existing work | Entry points |
|---|---|---|
| Linux/Arch client | Encrypted enrollment and identity loading, exact resource selection, protected Unix IPC, bounded agent RPCs, locked daemon, inactive user unit, supervised application and SSH access | [Client](docs/client-configuration.md), [IPC](docs/local-ipc.md), [agent](docs/agent-resource-streams.md), [service](docs/arch-user-service.md), [HTTPS](docs/application-https.md), [SSH](docs/ssh-application.md) |
| Dashboard | Inventory, exact access inspection, resource revisions/grants/hosting, user/device/connector lifecycle, invitations, factor registration/testing/retirement, audit and security views | [Dashboard source](internal/controller/dashboard), [management](docs/dashboard-management.md), [factors](docs/dashboard-factors.md), [lifecycle](docs/dashboard-lifecycle.md), [invitations](docs/dashboard-invitations.md) |
| Native administration | Go-held signer, restricted inherited-pipe bridge, sandboxed Electron window, encrypted administrator key, Linux command and development package, actual installed-window fixture | [Bridge](internal/adminbridge), [application](internal/adminapp), [key storage](docs/administrator-key-storage.md), [command](docs/administrator-command.md), [package](docs/administrator-package.md) |
| Administrator renewal | Hardware-approved same-key issuance, durable at-most-once issuance state, separate candidate activation TLS, retirement of old identity, native credential journal and resume flow | [Controller](internal/controller/admin_renewal.go), [HTTPS](internal/controller/admin_renewal_http.go), [native renewal](internal/adminapp/renewal.go), [renewal guide](docs/administrator-renewal.md) |
| Management destination | Actual administrator TLS, exact resource/revision/address/port, live grant and hosting checks, pinned dedicated connector, recheck inside each request transaction | [Route](internal/controller/management_route.go), [tests](internal/controller/management_route_test.go), [guide](docs/management-route.md) |
| Management relay foundation | Separate administrator-profile constructor, fixed connector ID, tighter connection/stream/lifetime limits and route-bound live admission callback | [Relay constructor](internal/carrier/management.go), [relay framing](internal/carrier/relay.go), [controller admission](internal/controller/management_carrier.go) |
| Recovery primitives | Encrypted, anchored snapshots and authenticated restore into quarantine; no remote recovery API or automatic unquarantine | [Recovery code](internal/controller/recovery.go), [guide](docs/recovery.md) |

## 3. Immediate next work: complete the private management connection

The committed relay foundation is not wired into a complete connector/native runtime. The destination gate still has a supplied loopback listener. Ordinary application access must not acquire administrator authority.

- [ ] Add dedicated real-TLS/gRPC tests for `ManagementRoute.NewCarrier` and `carrier.NewManagement`. Existing regression tests do not establish the new constructor's runtime behavior.
- [ ] Prove successful pairing of the actual administrator and the one configured connector, with exact opaque byte transfer and independent inner authentication.
- [ ] Reject ordinary device/service profiles, administrators on ordinary-device relay paths, wrong connector identities/certificates, wrong roots/deployments/pins, role reversal, forged identity fields and unconfigured connector selections.
- [ ] Test grant, hosting, resource revision, user/device, connector certificate and issuer revocation on reused outer TLS connections as well as new connections. Check expiry and ambiguous/future bindings.
- [ ] Exercise hostile configuration, malformed frames, abandoned pairing, deadlines, cancellation, backpressure, quotas, concurrent calls and shutdown. Prove all workers, slots, stream accounting and connections are released; do not use a response status as a substitute for socket observations.
- [ ] Implement the dedicated connector runtime with a fixed, reviewed management destination and connector possession checks. Join the outer carrier to the actual inner administrator TLS and destination gate. Admission to an opaque relay is not permission to open an arbitrary destination.
- [ ] Add native configuration and route selection for this management path. Keep root/pin/origin/resource/revision/connector selection in protected configuration; the renderer must not supply a target, key, file path, raw certificate or generic signing request.
- [ ] Integrate both ordinary administrator HTTPS and the separate renewal activation flow without allowing candidate certificates to use the dashboard before activation. Preserve at-most-once confirmation and recovery after ambiguous outcomes.
- [ ] Run the complete installed native command through the real intended management path: sign-in, exact hardware-approved mutation, renewal, revocation, reconnect, restart and bounded shutdown. Include negative controls and observed destination sockets.
- [ ] Produce a fresh management-path proof suitable for bootstrap finalization. A local health check, a relay READY frame or a component fixture is insufficient.
- [ ] Update the architecture/transport decision, management guide, threat model and evidence when the actual runtime is integrated. Keep ordinary client/connector semantics intact.

## 4. Phase 6: remaining Linux/Arch client work

| Work to finish | Evidence needed to close it |
|---|---|
| Supported Linux key-provider integration | Actual enrollment/signing/unlock/lock/renewal/revocation using the chosen Linux provider; no private-key export through IPC; explicit software/hardware capability; lost or unavailable provider fails closed. The existing encrypted-file baseline must not be described as hardware backing. |
| Complete IPC/application isolation | Real different-UID and hostile-origin tests for every exposed entry point, path ownership/replacement/race tests, bounded requests/streams, explicit same-UID limitations, no unintended TCP listener or arbitrary target gateway. |
| Desktop and browser access workflows | Real supported browser/media/Jellyfin and other promised Linux application flows, exact resource selection, preserved server name and TLS/application authentication, no certificate-verification workaround or broad proxy access. State unsupported combinations explicitly. |
| Installed client/service lifecycle | Fresh install, upgrade, removal, login/logout, daemon lock/unlock, duplicate instance, crash/restart and preserved private state on actual qualified Linux/Arch profiles. Existing package and user-manager fixtures are a baseline. |
| Real clock and suspend behavior | Actual suspend/resume, wall-clock/health faults and reconnect tests; no expired session revival, persisted lease reuse or forwarding before a fresh check. Qualify the intended time service and scheduling bounds. |
| Intermittent HTTPS/transfer failure | Reproduce and explain the authenticated transfer failure, implement a correction supported by a negative control and rerun real HTTPS/SSH/service flows. Passing repetitions alone do not establish its cause. |
| Compatibility and operating instructions | Supported distro/kernel/libc/architecture and dependency matrix, version/capability visibility, correct install/uninstall/recovery instructions, clear local-access scope and measured limitations. |
| Final combined-source qualification | Full quality and guarded Linux suites, installed Arch service, HTTPS and SSH flows, resource denial/expiry/revocation/socket scenarios; retained logs, skips, package provenance and source-matched artifact verification. |

Preserve the default of no global routes, DNS or VPN changes. Complete Linux-specific platform evidence here; cross-platform parity and Android/Windows implementation remain in their later phases.

## 5. Phase 7: secure owner bootstrap and finalization

Implement the durable ceremony in [BOOTSTRAP_AND_RECOVERY.md](BOOTSTRAP_AND_RECOVERY.md). The existing local administrator registration and two-key initial registration are primitives, not the complete ceremony.

- [ ] Authenticate the local host owner over the supported protected console/IPC mechanism. A loopback address alone is not owner authentication. Fresh and incomplete installations must not expose bootstrap or management publicly.
- [ ] Persist the complete state machine: `UNINITIALIZED`, `OWNER_PENDING`, `ADMIN_ENROLLED`, `ADMIN_ACCESS_VERIFIED`, `FACTORS_VERIFIED`, `RECOVERY_VERIFIED`, `READY_TO_FINALIZE`, `LOCKED_DOWN`.
- [ ] Establish owner/deployment identity, clock/storage health and short-lived single-use device-attempt-bound administrator enrollment. Generate the private key on the administrator device and prove it with fresh TLS.
- [ ] Verify real administration through the intended private management path after reconnect, with the stable hostname/WebAuthn origin and actual server-side device binding.
- [ ] Register primary and distinct backup hardware keys; require supported user verification and separate successful tests. Two virtual credential IDs do not prove two physical authenticators or independent custody.
- [ ] Establish and exercise independent local recovery, create encrypted offline backup material and successfully restore-test it in isolation before permitting finalization.
- [ ] Bind every proof to its relevant origin, root, device, management path/configuration and current authority. Invalidate and repeat affected proofs after changes.
- [ ] Make finalization atomic, durable and idempotent. Require fresh exact hardware approval, close bootstrap endpoints and invalidate bootstrap tokens/sessions without breaking normal private administration.
- [ ] Crash/restart and replay-test every transition, including storage/audit failure. Do not reopen anonymous setup, bypass failed proof or lock down before access/recovery succeeds.
- [ ] Show incomplete setup clearly in the UI; implement the required anti-lockout review and error/retry states.
- [ ] Complete BOOT-01–05 through actual processes, listeners and reconnects, retaining denial/socket and crash evidence.

## 6. Phase 7: independent recovery and administrator lifecycle

- [ ] Implement the local owner/maintenance recovery entry point and authentication policy, including independent recovery material. Document the limit that an attacker with host root cannot be excluded merely by calling a shell “physical.”
- [ ] Quarantine remote traffic and stop issuance before recovery; verify deployment identity and distinguish loss from compromise. No public reset endpoint, email/SaaS dependency or dependency on a working Portico tunnel.
- [ ] Exercise primary-factor loss with the tested backup key; retire the lost key and register/test its replacement without silently removing the final usable factor.
- [ ] Exercise administrator device/key loss and missed certificate renewal using another valid administrator or independent console. Generate a replacement key locally, revoke old authority and do not extend expired remote access.
- [ ] Exercise loss of both factors, intermediate/root compromise and controller-host compromise with the appropriate independent or clean-environment trust ceremony.
- [ ] Integrate backup creation/status, restore testing and custody into the supported ceremony. Retain the recovery anchor independently; exclude private device keys, live sessions/challenges and plaintext invitations.
- [ ] Handle authentic stale backups, revoked identities, consumed tokens, missing/wrong recovery keys, corruption/truncation, schema changes and release security floors. Remain quarantined when current authority cannot be proved.
- [ ] Protect temporary plaintext and cleanup across crashes; use an independently protected recovery journal when normal required audit/storage is unavailable. Do not grant authority while required audit persistence fails.
- [ ] Implement safe re-enrollment, authority reconciliation, repeat administration/factor/path checks and a deliberate audited exit from maintenance.
- [ ] Finish administrator lifetime/recurrence semantics, including Europe/London DST boundaries, expiry, failed renewal and independent recovery. Existing same-key renewal does not by itself prove ADMIN-03's schedule contract.
- [ ] Qualify the installed native renewal journal and provider reconciliation through real restart, storage fault, lost-response and activation scenarios on the complete management path. Do not automatically repeat uncertain signing or confirmation.
- [ ] Complete REC-01–06 and ADMIN-01–08 at the scope specified by the acceptance plan, including real supported hardware and a documented owner recovery drill.

## 7. Phase 7: complete dashboard coverage and usability

Audit each page against sections 20–22 of the preserved master requirements. Existing lists and component tests are useful starting points; fill absent data, actions and user flows without inventing status.

| Required page/area | Remaining completion check |
|---|---|
| Dashboard | Real status/security warnings, connectors, active sessions, expiring credentials and update/version status; truthful loading, empty, stale and unavailable states. |
| Users | Devices, resources, authorization expiry and revocation with effective scope and exact reviewed changes. |
| Devices | Fingerprint, platform, enrollment date, last seen, expiry and revoke; accurate status and identity binding. |
| Resources and connectors | Exact tuple/revision, assigned identities, hosting, connector status/version/last seen and provided resources; complete detail/edit/revoke flows. |
| Access and policies | Effective permissions, expiry and exact change previews; identical direct-API/UI enforcement, stale-preview rejection and operation-specific hardware approval. |
| Enrollment | Invitation creation, expiry, status and revocation; server-enforced secret delivery only after the required approval, no initial HTML/API secret leakage. |
| Security and administrators | Complete administrator lifecycle, factors, certificate policy/renewal, recovery status and anti-lockout handling. |
| Audit | Actor, target, timestamp, action and result; integrity/failure visibility, bounded pagination and safe rendering. |
| Updates and compatibility | Accurate controller/connector/client versions and incompatibility reasons. Full updater/signing implementation remains Phase 13; do not fabricate update availability or a working updater. |
| Backups/recovery/settings | Real supported operations, custody/restore-test status and required confirmations, tied to the completed local recovery boundary. |

- [ ] Verify Material Design 3 consistency, desktop/mobile layout, keyboard-only operation, focus order/trapping/restoration, touch targets, screen-reader labels/announcements, contrast and error states across all flows.
- [ ] Test hostile labels and audit rendering, CSRF/CORS/Host/rebinding, malicious origins/frames/windows, direct API requests with duplicate or unknown fields, privilege escalation and secret handling in caches/logs across all newly exposed surfaces.
- [ ] Complete actual supported hardware-key/origin and native OS isolation qualification; browser virtual authenticators are not physical evidence.
- [ ] Retain redacted screenshots, browser/native results and failure artifacts for the final source. Verify installed dependencies on an actual Arch desktop; the offline package fixture omits dependency installation and is not that proof.

## 8. Failures and evidence work that must not be forgotten

| Recorded issue/gap | Required next action |
|---|---|
| Intermittent authenticated HTTPS failure, including a failing main run with the same binary as a passing dashboard run | Preserve [shutdown-source evidence](docs/phase-6-shutdown-hosted-evidence.json) and earlier service logs; obtain a cause and a discriminating regression before claiming resolution. |
| Earlier terminal/transfer and SSH descriptor-child timeout failures | Revisit [client evidence](docs/phase-6-client-report.md), [terminal evidence](docs/phase-6-terminal-report.md) and [SSH identity evidence](docs/phase-6-ssh-identity-evidence.json); classify each cause and retain failures separately from passes. |
| Native shutdown timeout after functional browser checks | Preserve [clock evidence](docs/phase-7-native-clock-evidence.json) and local `management-mobile-regression-browser` reports. Fixture-owned exit and diagnostics improved qualification; later passes do not prove every historical timeout's cause. |
| Native renewal phone-width overflow at `84b4393` | Retain the [failed-source receipt](docs/phase-7-administrator-native-renewal-hosted-evidence.json). Layout was corrected; verify the subsequent actual renewal artifact, mobile measurements and screenshots before closing the artifact-level gap. |
| Current `d22e2c4` hosted archives | Fetch native/installed/Linux/service evidence while retained, verify published archive digests and embedded files, inspect actual test coverage/counts/skips and prove tested merge/source tree equality. Do not run downloaded executables on the developer host. |
| Historical `e4b13a6` archives | These were still unverified at the earlier checkpoint. Prefer current-source qualification; preserve older failure evidence. If an artifact has expired, report that and obtain a new source-specific run rather than inventing verification. |
| Documentation drift | Refresh older “not installed,” “pending” and renewal-status wording where newer source-specific evidence supersedes it. Keep historical reports intact and distinguish software proof from physical/deployment gates. |
| PR description and final integration | Update PR #5 with the final implemented scope and verified evidence. Keep it draft until appropriate; do not merge, release or deploy merely to finish this checklist. |

Raw local tools, downloads, VM images, private credentials, signing material and runtime caches are not part of a public save point. Publish only reviewed redacted evidence or hashes with accurate availability statements. Avoid duplicate large archive downloads; inspect free E: space before substantial builds.

## 9. Owner decisions and external qualifications

Continue independent software work using isolated `.test` origins and virtual authenticators while physical inputs are undecided. Do not keep asking for the same undecided values or manufacture substitutes.

| Decision/gate | What is still required |
|---|---|
| Q02 — private administrator origin | Owner-selected stable hostname/origin, trust and actual browser/native device-binding qualification through the intended path. |
| Q03 — two hardware keys | Primary/backup makes and models, supported UV/attestation policy and offline metadata procedure, distinct tested physical devices and independent backup custody. |
| Q06 — recovery | Deployment-specific host-owner authentication, independent recovery material, local interactive procedure and observed owner recovery drill. |
| Q08 — issuer | Issuer/root custody, isolation, supported rotation/compromise recovery and final integrated renewal qualification. Software renewal is implemented; production custody is not thereby qualified. |
| Q11 — platforms | Explicit supported OS/kernel/architecture/provider/dependency matrix and actual hardware/desktop/lifecycle evidence. |
| Q14 — policy/operations | Administrator lifetime and recurrence, audit retention, resource limits and operational recovery choices, with usability and failure evidence. |
| Q01/Q05/Q07 — remaining technical gates | Complete transport review/hostile-load testing, measured revocation/partition semantics and accepted limits, application/local-user isolation and honest access scope. |
| Q04/Q12 — deployment/network | Exact hostname/DNS policy and supported isolated networking/Mullvad profiles; full network hardening remains in later phases. |
| Q10/Q13 — release/governance | Actual release custodians and signed-distribution trust; owner decisions on license/name/governance, maintainer review and response commitments. Check remote required checks/branch protection rather than assuming local workflows configure them. |

Q09's Phase 2 local-storage decision is resolved; maintain transactional audit, migration, snapshot and quarantine guarantees as subsequent surfaces are added. Production governance/release/network decisions are recorded here without pretending they are already supplied or silently pulling their full implementation into Phase 6.

## 10. Complete outstanding acceptance inventory

The [canonical manifest](tests/acceptance/manifest.json) is unchanged. Implemented scenarios are AUDIT-01, CONN-01, CONN-03, CONN-04, PROTO-03, PROTO-04 and PROTO-05. Keep them passing on the final source.

The following **84 cases remain planned**, even where components provide partial coverage. For each, implement the complete scenario, inspect its real runtime observations and retain source/platform-specific evidence before changing its manifest status. The [acceptance plan](ACCEPTANCE_TEST_PLAN.md) supplies each exact fixture and expected result.

| Area | Planned cases | Count |
|---|---|---:|
| Authentication | AUTH-01–08 | 8 |
| PKI/enrollment | PKI-01–06 | 6 |
| Authorization | AUTHZ-01–08 | 8 |
| Connector scope | CONN-02 | 1 |
| Administrator protection | ADMIN-01–08 | 8 |
| Session timing | SESSION-01–06 | 6 |
| Network isolation | NET-01–08 | 8 |
| Mullvad coexistence | VPN-01–05 | 5 |
| DNS | DNS-01–04 | 4 |
| Recovery | REC-01–06 | 6 |
| Bootstrap | BOOT-01–05 | 5 |
| Updates | UPDATE-01–06 | 6 |
| Secret handling | SECRET-01–04 | 4 |
| Transport/resource limits | PROTO-01–02 | 2 |
| Audit | AUDIT-02–04 | 3 |
| Platform parity | PLATFORM-01–04 | 4 |

Close scenarios required by the completed Phase 6/7 behavior; retain later-phase cases as pending. Full cross-platform, network, VPN/DNS, update and independent audit qualification remains part of eventual project completion, not permission to start Phase 8 now. Do not equate 20 regression tests, hundreds of unit tests or seven green workflows with 91 complete acceptance scenarios.

## 11. Later project phases — recorded, not started by this save point

| Phase | Work still required after the owner's next-phase approval |
|---|---|
| 8 — Windows | Supported Windows client first, then connector: CNG/ACL/service and local-user boundaries, real resource/application flows, suspend and security parity. Portable Windows development tests do not qualify this phase. |
| 9 — Android | Required client with Kotlin/native integration, actual Keystore handles, real devices/apps, lifecycle/Doze/background/suspend tests and honest coexistence with Mullvad's VPN slot. Android connector is optional, not a substitute for the client. |
| 10 — Network hardening | Qualified controller/connector service deployment and Compose profile; one-public-infrastructure-port design where practical; independent LAN/Docker/IPv6/NAT/metadata egress containment, hostile tests, dry run, timed rollback and console recovery. |
| 11 — Mullvad/DNS | Real isolated coexistence/kill-switch/qBittorrent tests, no unintended Internet gateway, measured DNS invariance and exact pinned-answer hostname behavior before optional split DNS. |
| 12 — SSH CA | Separate restricted short-lived SSH certificate issuance and review, local SSH key custody, explicit authorization and real authentication tests. Existing SSH resource transport does not implement this CA. |
| 13 — Updates | Authenticated artifacts and manifests, actual signing/TUF custodians, expiry/rollback floors, capability compatibility, staged update/install/recovery and key rotation drills. Do not claim a supported unsigned interim distribution. |
| 14 — Audit/hardening | All 91 complete scenarios; implementation-aligned threat/control review, manual custom-code review, independent security review and resolution of critical/high findings. |

Across earlier phases, keep issuer/PKI, exact policy, transactional audit, connector isolation, dependency provenance and design documents synchronized with the final integrated system. See the delivery ledger for inherited gates.

## 12. Restart instructions and completion gate

1. Read this save point, current Git status/history, PR #5 and the latest workflow/artifact state. Prefer current observations to old notes. Do not discard uncommitted work or overwrite prior evidence.
2. Keep all source, build output, caches, downloads and reports on E:. Read the supplied scripts before invoking platform/container/installed-runtime harnesses; those belong in their guarded NIC-less guest or disposable runner, not the developer host.
3. Start with the dedicated management carrier tests and complete connector/native integration in section 3, then bootstrap/finalization, recovery and the remaining Phase 6/platform/dashboard work. Hardware decisions need not prevent independent software work.
4. Use meaningful negative tests and real socket/process observations. Run the relevant local checks, then final-source hosted Windows/Linux quality, native/installed-window, Arch package/service, HTTPS/SSH and guarded Linux qualification. Investigate new failures instead of repeatedly rerunning until green.
5. Verify downloadable evidence, update the checklist/ledger/PR, commit and push coherent changes. Keep logs, hashes, skipped tests, failures and remaining limitations explicit.
6. Audit every Phase 6/7 requirement against the actual final source and supported runtime evidence, including owner-dependent physical/recovery gates. Only declare completion when all applicable requirements are proved. Then stop and wait for approval before Phase 8.

For the already available focused Windows regression, use PowerShell 7 from the E: checkout:

```powershell
Set-Location 'E:\Portico-dashboard'
. ./scripts/env.ps1 -WorkRoot 'E:/Portico/work'
$env:GOMAXPROCS = '2'
$env:CGO_ENABLED = '1'
go test -race ./internal/carrier ./internal/controller -run '^(TestCarrier|TestRelay|TestManagement)' -count=1 -v -timeout 5m
./scripts/check-docs.ps1
```

Use a fresh E: report name when retaining another run. [scripts/check.ps1](scripts/check.ps1) is the complete repository gate; [scripts/test-linux.ps1](scripts/test-linux.ps1), [native qualification](scripts/test-native-admin.ps1), [installed native qualification](scripts/test-installed-native-admin.ps1) and [Arch user-service qualification](scripts/test-arch-systemd.ps1) have separate prerequisites and isolation requirements. Do not blindly run all harnesses simultaneously; in particular, keep heavy builds separate from actual native-window timing tests.

No deployment, release, merge, developer-host DNS/firewall/Mullvad/clock/service/global-trust change or Phase 8 start is authorized by this save point. Preserve the owner's existing work and the current hardware/hostname decision status.
