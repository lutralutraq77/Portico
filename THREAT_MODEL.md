# Threat model

Status: Phase 0 design review, not a penetration-test report.

## Assets and attacker model
Protect private resource reachability, device and CA keys, administrative authority, policy integrity, revocation freshness, recovery material, audit evidence, release authenticity and Mullvad-contained Internet traffic.

Attackers may be unauthenticated Internet callers, ordinary enrolled users, malicious clients, LAN hosts, resource applications, connectors, relays, malicious websites visited by an administrator, supply-chain operators, or a privileged host attacker. Assume packet tampering, replay, dropped control messages, DNS rebinding, certificate copying, stale backups and clock faults. Denial of service is possible; contain cost and never convert outages into access.

## Threat register
Severity is prospective impact, not an existing vulnerability finding.

| ID | Attack / boundary | Severity | Required response | Residual risk / proving test |
|---|---|---|---|---|
| TH-01 | Change username/header to impersonate another device; TB-03/06 | Critical | INV-01/16: verified key and registered immutable identity | Stolen usable device key impersonates that device; AUTH-01–08 |
| TH-02 | Change destination/port, exploit wildcard or IPv6 alias; TB-04/05 | Critical | INV-02: server-controlled tuple and revision; normalize IP | Authorized application may proxy onward; AUTHZ-01–07 |
| TH-03 | Connector registers an arbitrary host or calls admin APIs; TB-04 | Critical | Independent HostBinding and typed method authorization | Connector root abuses OS reachability; CONN-01–04 |
| TH-04 | Relay substitutes endpoint or reads traffic; TB-02/03 | High | Inner mTLS verifies expected connector and client | Timing metadata and denial remain; PROTO-01–03 |
| TH-05 | Steal invitation, replay redemption, alter CSR identity; TB-02/07 | High | Short expiry, single-use atomic reservation, CSR proof, trusted onboarding | Bearer invitation stolen before use can win race; optional out-of-band CSR confirmation for sensitive enrollment; PKI-01–03 |
| TH-06 | Stolen admin certificate renews forever or grants resources; TB-06/07 | Critical | Independent fresh hardware-key operation approval; issuer paths closed | Malware can act during valid approval; ADMIN-01–06 |
| TH-07 | CSRF, XSS, DNS rebinding against local admin agent; TB-01/06 | Critical | Strict origins/hosts, no arbitrary CORS, server step-up, no generic signer | XSS can manipulate a displayed operation; independent hardware touch does not attest human understanding; ADMIN-07–08 |
| TH-08 | Revocation event dropped; stale stream survives; TB-03/04 | Critical | Online new decisions; finite leases, cancellation and monotonic deadlines | Bounded in-flight/queued bytes cannot be recalled; SESSION-02–06 |
| TH-09 | Old backup restores revoked key or consumed token; TB-12 | Critical | Quarantined recovery; no automatic identity reactivation | Unreconciled data requires full re-enrollment; REC-05–06 |
| TH-10 | Docker publication, IPv6, second NIC bypass Portico; TB-05 | Critical | Independent ingress segmentation + complete forwarding filters | Root can change boundaries; NET-01–08 |
| TH-11 | Portico changes route/DNS and torrent traffic escapes; TB-11 | Critical | Separate routing domain; fail-closed torrent egress; no exit API | Existing misconfiguration cannot be fixed by a Portico claim; VPN-01–05 |
| TH-12 | DNS answer switches resource to management/metadata host; TB-05 | Critical | Approved concrete IP set, no re-resolve after check; protected-target exclusions | DNS cannot establish application identity; DNS-02–04 |
| TH-13 | Root/intermediate stolen or signing endpoint abused; TB-07/09 | Critical | Offline root, restricted issuer profile and provisioner, explicit active issuer list | Root signing compromise requires new trust root; PKI-05–06, REC-03 |
| TH-14 | Bootstrap closes before admin/recovery works or opens publicly; TB-06/09 | High | Durable staged state and locally authenticated setup | Lost host and all recovery material may be unrecoverable; BOOT-01–05 |
| TH-15 | Supply-chain update installs malware or rolls trust back; TB-10 | Critical | Signed metadata, offline release root, staged install, security floor | Compromised signing quorum can authorize malware; UPDATE-01–06 |
| TH-16 | Token/key in HTML, logs, telemetry, crash dump or image | High | Allowlist output, one-time delivery, no browser persistence, no secrets in command lines | A user may copy a revealed invitation; SECRET-01–04 |
| TH-17 | Audit mutation lost or fabricated on disk; TB-08 | High | Atomic outbox, external append-only export, gap detection | Root can erase local evidence before export; AUDIT-01–04 |
| TH-18 | Slow streams, huge CSR, HTTP/2 reset flood, disk exhaustion | High | Bounded queues/concurrency, budgets, timeouts, no unbounded buffering | Finite resources can still be exhausted; PROTO-04–05, AUDIT-03 |
| TH-19 | Counterfeit/swappable software authenticator presented as hardware | High | UV required plus vetted attestation policy and non-backup-eligible credentials | Hardware status cannot be inferred from “cross-platform” hint alone; Q03, ADMIN-05 |
| TH-20 | Loopback service used by another local OS user; TB-01 | High | OS-scoped IPC or explicit single-user mode with documented scope | TCP loopback alone exposes the enrolled device's access to local processes; PLATFORM-02 |
| TH-21 | Authorized SSH/proxy/Jellyfin exploitation becomes LAN pivot; TB-05 | Critical | Application auth, SSH forwarding restrictions where desired, workload egress segmentation | Port/identity policy cannot inspect arbitrary application semantics; NET-07, AUTHZ-07 |

## Threats requiring decisions before implementation
Q01: relay and inner-TLS adapter behavior under cancellation, suspend and malformed frames.
Q02: browser certificate factor, stable private WebAuthn origin and bootstrap transition.
Q03: compatible independently held hardware authenticators and offline attestation policy.
Q04: per-resource DNS approval without accidental broad trust.
Q06: what counts as independently evidenced physical recovery on each supported host.
Q07: local application access on shared desktop devices.

Until these gates close, there is no production deployment profile.

## Review procedure
For every new feature, identify crossed boundaries, update threats, add mechanism rows and map to negative tests. Consider a malicious implementation of each peer, not just malformed requests from the official client. Review combined faults: revocation plus controller outage, backup rollback plus valid old certificate, IPv6 plus Docker restart, or Mullvad failure plus connector restart.

A future release needs adversarial review of all Portico-specific authorization/state-machine code and platform integration, independent review of key handling and recovery, and verified findings closure. Passing functionality tests does not demonstrate absence of vulnerabilities.
