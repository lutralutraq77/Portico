# Security acceptance test plan

Status: **91 specified cases; AUDIT-01, CONN-01, CONN-03, CONN-04 and PROTO-03 implemented; 86 cases remain planned.** This document is the canonical specification; run-specific results are in the [Phase 2 report](docs/phase-2-report.md), [connector isolation report](docs/phase-5-isolation-report.md) and [lifecycle report](docs/phase-5-lifecycle-report.md). The socket/process cases require the isolated Linux guest; exclusion or a skip on other hosts is not passing evidence. Optional-feature tests are deferred only while those features are absent; required MVP platform tests are not optional.

## Harness and evidence
After Phase 1 authorization, establish deterministic domain tests, property/fuzz tests, integration tests with malicious peers and real OS/network labs. Mock cryptography never proves authentication. Use mature TLS implementations with separate keys/roots and actual handshake failures.

Lab nodes: controller/issuer, relay, two connectors, two users with at least two devices each, dual-stack workload hosts with Jellyfin-like HTTP/SSH/neighbor ports, untrusted LAN, owned Internet sink and isolated VPN/torrent namespace. Place labs on E: during this development; never alter the real machine's routes/firewall/Mullvad. No public scanning or third-party torrent payloads.

For each run retain build/revision, dependency versions, OS/kernel/Engine/backend, fixture IDs, monotonic timestamps, expected result, redacted actual result and packet/socket evidence. Every negative network test pairs a positive control proving the service and instrumentation worked. Observe destination accept/SYN counters and untrusted-LAN reachability; an API denial alone is insufficient.

Timing targets come only from [session design](SESSION_AND_REVOCATION_DESIGN.md): 2-second connected cancellation and 15-second request-anchored lease plus at most 1-second scheduling tolerance in the qualified environment. Explicitly distinguish in-flight/queued bytes from fresh forwarding. Test at boundaries, under loss/reordering, and after suspend.

Virtual FIDO authenticators permit deterministic negative tests but cannot prove hardware attestation or physical independence. Real primary/recovery keys and real Android/Windows devices are required for their gates. Synthetic VPN tests precede actual isolated Mullvad coexistence; neither substitutes for the other.

## Test cases
The phase shown is the earliest meaningful executable gate. Some tests span several later phases. The manifest records current implementation status; component-only coverage does not satisfy a full scenario.

### Authentication — earliest Phase 3

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| AUTH-01 | Use Alice's username with no certificate, another device key, or a forged identity header | Authentication fails; Alice's resources receive no socket attempt. |
| AUTH-02 | Use expired/not-yet-valid leaves and a valid leaf with the wrong private key | TLS/registry boundary rejects; no application bytes flow. |
| AUTH-03 | Revoke a device, then try each of its active/overlapping leaf certificates | Every credential denies new sessions after commit. |
| AUTH-04 | Rename user/device or submit a different name in requests | Principal and effective grant set remain the original immutable identity. |
| AUTH-05 | Replay a session/pair identifier from another device or connector | No impersonation/resumption; possession of the ID is insufficient. |
| AUTH-06 | Enroll on each platform and inspect server responses/state, logs, image and backup fixtures | Only public key/CSR/certificate metadata is present; device key never leaves key provider. |
| AUTH-07 | Use wrong EKU, CA leaf, unexpected SAN, foreign deployment or wrong certificate profile | Every malformed/incorrect profile rejects. |
| AUTH-08 | Use connector/service certificate on admin APIs; use unregistered leaf from an otherwise trusted issuer | No admin/user role inference; unregistered or inactive issuer/leaf rejects. |

### PKI and enrollment — earliest Phase 3

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| PKI-01 | Submit CSR with extra admin SAN, changed device ID, excessive lifetime or invalid signature | Server ignores no dangerous input silently: request rejects; issuer uses approved profile only. |
| PKI-02 | Redeem one invitation concurrently with two different keys, then replay it | Exactly one CSR reservation; at most the single bound enrollment becomes active. |
| PKI-03 | Crash between reservation, issuer response and activation; retry identical and altered attempts | No reusable anonymous token, unlimited issuance or active unregistered leaf; identical retry reconciles safely. |
| PKI-04 | Compare planned overlap with lost/stolen replacement | Only explicit overlap survives to its deadline; compromise replacement immediately revokes old credentials and cancels streams. |
| PKI-05 | Attempt direct CA/provisioner/token renewal without Portico approval, including stolen admin certificate | No bypass of registration authority and fresh admin hardware approval. |
| PKI-06 | Rotate/disable an intermediate and test offline clients, old chains and clean replacement | Inactive issuer rejects; staged clean trust works; offline devices have documented re-enrollment path. |

### Authorization — earliest Phase 4

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| AUTHZ-01 | Grant only Alice/Pixel Jellyfin at one tuple and connect using the official and hostile clients | Authorized session reaches the designated service; every other fixture begins denied. |
| AUTHZ-02 | Request SSH and every other test port on the Jellyfin host | Zero destination SYN/socket attempts for denied tuples. |
| AUTHZ-03 | Request another LAN host, subnet, wildcard and port range | Input/authorization rejects; no network expansion. |
| AUTHZ-04 | Supply destination overrides, mapped IPv6, alternate IP encodings, URLs and metadata targets | Canonical validation denies ambiguity and protected targets. |
| AUTHZ-05 | Grant user access on one selected device, enroll another device, disable user/device/resource in turn | New device inherits nothing; each disable blocks affected access. |
| AUTHZ-06 | Change resource endpoint/connector while retaining ID; replay old revision/preview | Old grants/HostBindings cannot authorize new tuple; fresh approval required. |
| AUTHZ-07 | Attempt arbitrary CONNECT/SOCKS/Internet gateway behavior; exercise a deliberately permitted proxy/SSH resource | Portico has no arbitrary target gateway; application-mediated onward access is contained by workload egress, with residual behavior documented. |
| AUTHZ-08 | Submit identical mutations via UI and direct API, add mass-assignment/unknown/duplicate fields and race a preview | Same checks/outcomes; ambiguous fields reject; changed preview requires reapproval. |

### Connector scope — earliest Phase 5

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| CONN-01 | Connector A hosts its assigned resource; connector B advertises the same or an unassigned resource | A succeeds only with HostBinding; B cannot advertise/open that service. |
| CONN-02 | Use a connector certificate to create users/grants or modify security settings | Every management mutation rejects with no state change. |
| CONN-03 | Use a hostile connector to request leases for another connector, resource revision or unrelated session | Controller rejects cross-connector scope; local socket confinement is evaluated separately. |
| CONN-04 | Disable/revoke connector during active traffic, restart it and replay prior hosting/session state | All dependent sessions close; no old lease/HostBinding resurrects. |

### Administrator protection — earliest Phase 3

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| ADMIN-01 | Perform every sensitive operation with only a valid administrator certificate | No mutation or invitation plaintext without fresh verified hardware approval. |
| ADMIN-02 | Steal current admin certificate and repeatedly request renewal/longer authority through every API | Authority cannot extend indefinitely; issuer side paths also reject. |
| ADMIN-03 | Use daily Europe/London schedule across spring/autumn change, ambiguous/nonexistent times and failed renewal | Preview/UTC interval matches documented rule and cap; expiry closes admin access and console recovery works. |
| ADMIN-04 | Replay assertion/challenge, change operation/device/revision, or reuse approval for a second mutation | No mutation; approvals are single-use and exact-operation-bound. |
| ADMIN-05 | Try touch-only, synced/software, invalid attestation, UV=false and counterfeit hardware claims | Supported hardware profile enforced; uncertain hardware status never silently treated as independent factor. |
| ADMIN-06 | Revoke admin/factor and try browser sessions, outstanding challenges and enrollment/factor removal | Revoked admin sessions/challenges fail; last-factor changes cannot silently lock owner out. |
| ADMIN-07 | Launch malicious website against local bridge/private management; test CSRF, CORS, Host spoof and rebinding | No cross-origin mutation, device impersonation or generic signing/forwarding. |
| ADMIN-08 | Place XSS-shaped values in labels/audit and attempt invitation retrieval before step-up | Values safely rendered; no secret appears in initial HTML/API; UI/API authorization is identical. |

### Session timing — earliest Phase 5

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| SESSION-01 | Exercise every certificate/authority/grant/session/idle deadline at just-before, equal and after | Earliest deadline wins; fresh certificates do not extend existing sessions. |
| SESSION-02 | Revoke under normal network conditions while observing destination sockets | New decisions after commit deny; connected socket closure target is 2 seconds. |
| SESSION-03 | Drop cancellation/control messages and partition controller under continuous bidirectional traffic | No forwarding beyond 15-second request-anchored lease plus 1-second qualified scheduling tolerance. |
| SESSION-04 | Race activation, resource/grant mutation, replacement and explicit session termination | No stale-revision activation; terminated IDs cannot reactivate; documented bounded race only. |
| SESSION-05 | Delay/duplicate/reorder renewal replies, reconnect and replay session IDs | Receipt time does not extend lease; wrong sequence/identity/session rejects. |
| SESSION-06 | Suspend/resume, kill/restart process, roll wall clock back, exceed clock-health threshold | No persisted lease resumes; checks precede any new forwarding; unknown time fails closed. |

### LAN, Docker and application isolation — earliest Phase 10

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| NET-01 | Probe protected services from independent untrusted LAN over IPv4 with Portico stopped/running | LAN cannot directly reach resources; authorized Portico connection succeeds. |
| NET-02 | Repeat with IPv6 global/ULA/link-local and IPv4-mapped forms | No family/address bypass; same allow/deny semantics. |
| NET-03 | Accidentally publish a protected container port on all interfaces in the isolated lab | Independent boundary still denies LAN; configuration detector identifies exposure. |
| NET-04 | Repeat isolation with Docker iptables and separately qualified nftables backend | Correct forwarding and host chains apply; no assumption of identical chains. |
| NET-05 | Reboot host/daemon, restart containers and change network interface order | Isolation remains or deployment safely quarantines; no transient exposed service accepted as passing. |
| NET-06 | Test second NIC, direct container route, host networking and bridge reachability | Supported profile stays isolated; unsupported topology is rejected/reported, never advertised secure. |
| NET-07 | Compromise a workload fixture and connector fixture; try neighboring services, Docker socket, router and management | OS/network boundaries restrict actual reach; application-mediated pivots and root limits are recorded honestly. |
| NET-08 | Exercise proposed firewall plan in VM with failed health check and lost remote admin | Timed rollback works, physical console works, persistence requires successful verification. |

### Mullvad coexistence — earliest Phase 11

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| VPN-01 | Run harmless owned torrent workload through qualified Mullvad client while opening Portico resources | Torrent payload exits only through Mullvad; resource access matches grants. |
| VPN-02 | Kill VPN/client, remove tunnel, disrupt DNS and reconnect under payload generation | No plaintext torrent egress on physical/Portico interfaces; kill switch persists. |
| VPN-03 | Start/stop/restart Portico and compare route, DNS and kill-switch snapshots | No unauthorized changes; no alternate torrent route. |
| VPN-04 | Ask Portico to act as Internet exit or send torrent traffic via connector | No gateway capability or successful arbitrary egress. |
| VPN-05 | Test real supported client platforms with Mullvad and Android one-VPN conflict | Coexistence modes match documented support; no silent replacement/disabling of VPN. |

### DNS — earliest Phase 11

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| DNS-01 | Compare resolver, hosts file, route and DNS traffic before/after install/start/stop/uninstall | Default installation makes no global DNS/route changes. |
| DNS-02 | Change hostname A/AAAA/CNAME to unapproved host/metadata/IPv6/mixed answers | New hostname sessions pause/deny until reviewed revision. |
| DNS-03 | Race DNS resolution and dial; simulate NXDOMAIN/timeout/poisoning | Dial uses validated literal IP; no unsafe fallback/re-resolution; IP resources and recovery remain usable. |
| DNS-04 | When optional split DNS exists, test suffix overlap, public names and uninstall | Only explicitly configured private zones change; previous resolver behavior restores. |

### Recovery — earliest Phase 3

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| REC-01 | Lose administrator private key | Another valid admin or local console enrolls replacement; no server key download exists. |
| REC-02 | Miss admin renewal with remote access unavailable | Independent local procedure restores administration; expired cert never accepted remotely. |
| REC-03 | Simulate intermediate and root compromise/loss separately | Appropriate quarantine/clean trust ceremony succeeds; compromised root cannot authenticate its sole repair. |
| REC-04 | Use backup hardware key, then lose both factors | Backup handles second-factor loss; both-factor loss requires independent console path. |
| REC-05 | Restore an old but authentic backup predating revocation/token consumption | Quarantine; no old session/invitation or revoked identity reactivates; uncertain freshness forces re-enrollment. |
| REC-06 | Tamper with/truncate encrypted backup, omit key material, use wrong key or stale release floor | Restore rejects corruption; loss is reported; trust/security floor cannot roll back. |

### Bootstrap — earliest Phase 3

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| BOOT-01 | Probe fresh/incomplete setup from LAN/Internet in isolated VM | Bootstrap/management unreachable remotely; local owner authentication still required. |
| BOOT-02 | Try finalization before actual admin-path proof, both keys or recovery restore test | Transition rejects and remains recoverable. |
| BOOT-03 | Crash/restart each setup transition and replay bootstrap token | Durable state is consistent; anonymous bootstrap and consumed tokens do not reopen. |
| BOOT-04 | Complete ceremony, finalize, then reconnect through actual management path | Management succeeds; bootstrap paths/tokens are closed. |
| BOOT-05 | Change origin, root, admin device or management path after verification | Affected evidence invalidates and relevant tests must repeat. |

### Updates — earliest Phase 13

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| UPDATE-01 | Present forged signature, wrong hash/size/architecture, missing threshold and modified manifest | No installation; trust decision independent of download TLS. |
| UPDATE-02 | Replay old signed metadata/target, freeze freshness, roll local clock or security floor back | Rollback/freeze checks reject; no silent downgrade. |
| UPDATE-03 | Import valid and expired offline update bundles | Valid bundle verifies with existing trust; expired metadata blocks update, not current resource access. |
| UPDATE-04 | Install a signed test build that breaks admin/resource health and simulate power loss | Staged rollback/recovery restores working compatible build; local console survives. |
| UPDATE-05 | Attempt binary rollback across incompatible database migration | Preflight blocks unsafe rollback; policy/revocation state is not reverted for convenience. |
| UPDATE-06 | Compromise online signing key, rotate delegated/root trust and test offline clients | Threshold/rotation/recovery rules hold; private keys never enter PR jobs. |

### Secret handling — earliest Phase 3

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| SECRET-01 | Create/redeem invitations while tracing HTML, API, URLs, logs and metrics | Plaintext appears only in approved one-time delivery and redemption; redacted elsewhere. |
| SECRET-02 | Read invitation list/details or request another user's secret before/after consumption | Metadata only; hash cannot be redisplayed; lost delivery requires approved replacement. |
| SECRET-03 | Inspect browser storage/cache, error reports, crash diagnostics, backups and images with canary secrets | No secret persistence/leak; no-store and output allowlists hold. |
| SECRET-04 | Cause validation/issuer/network errors with secret-bearing inputs | Structured error/correlation only; no reflection of token/key/body. |

### Transport and resource limits — earliest Phase 5

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| PROTO-01 | Malicious relay substitutes connector, client identity or stream pairing | Inner TLS/registry rejects; no application plaintext visible at relay. |
| PROTO-02 | Attempt downgraded TLS, unknown required capabilities and replayed early/resumed traffic | No protocol/security downgrade; initial no-resumption/no-early-data policy holds. |
| PROTO-03 | Test bidirectional data, half-close, cancellation and abandoned stream | Integrity/order preserved; semantics documented; no orphan sockets or cross-stream data. |
| PROTO-04 | Fuzz frames, CSRs, field duplication, giant/compressed bodies and HTTP/2 resets | Bounded failure, no crash/permit/secret leak; input limits enforced. |
| PROTO-05 | Slow-read/write and reconnect flood under set quotas | Bounded buffers/concurrency; cancellation releases resources; overload denies safely. |

### Audit — earliest Phase 2

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| AUDIT-01 | Crash around policy/security mutation and audit append | State and audit intent both commit or neither; no unaudited permit. |
| AUDIT-02 | Drop/reorder export, alter/delete local events and reconnect exporter | Sequences/gaps detected; independent previously exported evidence preserved. |
| AUDIT-03 | Exhaust audit/state disk during allow and emergency revoke/shutdown | No new grants/permits; emergency containment remains possible and failure is visible. |
| AUDIT-04 | Exercise issuance, login, revoke, factor/recovery/security changes, session end and update | Required redacted actor/target/time/result events exist, with no secret values. |

### Platform parity — earliest Phase 8

| ID | Adversarial setup / action | Required oracle |
|---|---|---|
| PLATFORM-01 | Run identical hostile-client/grant/expiry vectors on all required clients/connectors | Equivalent security outcomes; cross-compile alone is insufficient. |
| PLATFORM-02 | Attempt local listener/IPC use from another OS user or malicious origin | Mode matches documented scope; shared-user claims require enforced OS identity. |
| PLATFORM-03 | Generate and use keys through Windows CNG/Android Keystore/Linux provider | No private-key export through bridge; hardware/software capability labeled accurately. |
| PLATFORM-04 | Use Android real apps under Doze/background/suspend/reconnect and desktop suspend | No expired-session revival, silent VPN switch or insecure app certificate workaround. |

## Completion rules
A test has passed only with retained evidence against the candidate implementation and supported platform/profile. Skipped or unimplemented tests are not passes. Unsupported platforms are reported, not removed from the required MVP silently. No known critical/high finding may remain open at production approval.

Before production, independently review the threat model, all Portico-specific authorization/state transitions, issuer renewal paths, recovery, browser/agent interface and network isolation. Check that documentation matches measured behavior and every security-control row has evidence. Re-run affected suites for changes to protocol, key providers, policy, firewall profiles, time semantics and dependencies.

Phase 0 exit checks only document completeness, cross-reference consistency, source provenance and explicit unresolved decisions. It cannot validate any runtime security property.
