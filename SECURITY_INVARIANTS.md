# Security invariants

Status: normative requirements for future implementation. A conflict must stop the affected work and be recorded in OPEN_QUESTIONS.md; convenience must not silently weaken a requirement.

| ID | Invariant | Enforcement and evidence |
|---|---|---|
| INV-01 | Identity comes from proof of the locally held device private key and an active registered certificate, never a username, header, resource ID, or bearer session ID alone. | TLS boundary + certificate registry; AUTH-01–05 |
| INV-02 | Default deny. A resource grant permits one enabled resource revision, connector, concrete address and port/protocol; no sibling ports, subnet, LAN or Internet forwarding follows. | Controller + connector + constrained socket API; AUTHZ-01–07 |
| INV-03 | Dial and host permissions are independent. A connector may host only assigned resources and cannot administer the controller. | Typed principals + HostBinding; CONN-01–04 |
| INV-04 | User/device private keys are generated on their device and never stored centrally for download, in backups, logs or images. | Device key provider + issuance input contract; AUTH-06, PKI-01 |
| INV-05 | Permission increases, invitations, admin renewal, CA/recovery changes and other sensitive actions require a fresh single-use hardware-key approval bound to the exact operation and authenticated admin device. | Management authority + WebAuthn; ADMIN-01–06 |
| INV-06 | Certificate, authority, grant, session, idle and step-up deadlines are distinct; uncertainty never extends any deadline. | Controller + connector timers; SESSION-01–06 |
| INV-07 | Revocation denies new authorization on authoritative commit and cancels active sessions; partition behavior obeys finite leases. Issuing a replacement alone never revokes an old certificate. | Durable state + cancellation + leases; SESSION-02–05, PKI-04 |
| INV-08 | LAN isolation is a supported deployment property proven across IPv4, IPv6, Docker forwarding and alternate interfaces, independent of client honesty. | Deployment segmentation + host filters; NET-01–08 |
| INV-09 | Secrets are absent from ordinary logs, URLs, initial HTML, browser persistence, repository, crash reports and images. Redaction occurs before serialization. | API allowlists + logging contracts; SECRET-01–04 |
| INV-10 | Bootstrap is local and cannot finalize until working administration and independently tested recovery exist. Recovery never requires the current Portico tunnel. | Bootstrap state machine + OS recovery authority; BOOT-01–05, REC-01–04 |
| INV-11 | Default installation changes neither host default route nor global DNS and provides no exit node. Server Mullvad and the torrent kill switch remain independent. | Process/network boundaries; VPN-01–05, DNS-01 |
| INV-12 | Established cryptographic primitives, TLS and reviewed parsers/libraries provide security. Portico invents no encryption or secure transport protocol. | Dependency review + transport review; PROTO-01–05 |
| INV-13 | A security state change and its redacted audit intent commit atomically. No permit if required authoritative storage fails. Emergency denial remains possible during logging failure. | Transactional outbox + local emergency procedure; AUDIT-01–04 |
| INV-14 | Authentic releases, compatibility checks, safe rollback and preserved trust state precede installation. “Latest” and TLS download alone are not release authentication. | Verified metadata + staged installer; UPDATE-01–06 |
| INV-15 | API and GUI share server-side operation handlers, input validation, CSRF/origin defenses and effective-access computation. UI hiding grants no security. | Management API; ADMIN-07–08, AUTHZ-08 |
| INV-16 | CA validity does not imply a role. Every peer is restricted by registered certificate profile, active issuer and purpose; service certificates cannot become admin certificates. | Role-specific verifier + registry; AUTH-07–08 |
| INV-17 | Restoring an old backup must not reactivate revoked identities, stale sessions, consumed invitations or obsolete release trust. | Quarantined restore + re-enrollment; REC-05–06 |
| INV-18 | Portico cannot silently weaken these semantics on Windows or Android. Unsupported secure behavior blocks that platform's support claim. | Shared acceptance fixtures + platform testing; PLATFORM-01–04 |

Numeric timings and state-transition rules are owned by [session design](SESSION_AND_REVOCATION_DESIGN.md), not by a copied constant in this document.

## Limits of the promise
A device compromise permits misuse of that device's existing grants. Non-exportable keys reduce theft but do not prevent malware from requesting signatures. An administrator with both required factors can make dangerous grants. Controller root can change policy, steal online secrets and tamper with local records. Connector root can ignore its own proxy code and access anything its OS/network allows. Network authorization cannot stop a permitted SSH server or application from opening onward connections.

Therefore independent segmentation, destination authentication and least-privilege workloads remain necessary. A security review must evaluate these residual risks rather than interpreting “zero trust” as elimination of trust.
