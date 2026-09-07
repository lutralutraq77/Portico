# Roadmap and Phase 0 handoff

Status: phases 0–2 have foundation evidence. Phase 3 has verified issuer/admin/recovery software with physical and deployment gates open. Phase 4 policy software is implemented and under qualification. The active objective covers all fifteen phases; see the [delivery ledger](docs/delivery-status.md).

## Delivery phases and gates
| Phase | Scope | Required exit evidence |
|---|---|---|
| 0 — Research/design | Required 17 documents plus protocol/control/source/decision registers | Complete cross-referenced package, explicit risks and questions; no runtime claims |
| 1 — Repository/quality foundation | Repository structure, CI, formatting/linting, dependency/secret/vulnerability scanning, test harness and isolated development environment | Reproducible empty build/test path, pinned tools/actions, least-privilege CI, no production network access |
| 2 — Controller domain | Users/devices/connectors/resources/grants/certificate metadata/sessions/audit | Default-deny domain fixtures, transaction/outbox/crash consistency; no real networking |
| 3 — PKI/enrollment | Local keys, restricted issuance, expiry/revocation, admin step-up and recoverable bootstrap foundations | AUTH/PKI/ADMIN/BOOT/REC gates; resolve Q02/Q03/Q08 before dependent work |
| 4 — Policy engine | Exact grants/HostBindings/revisions, server-side previews | AUTHZ tests including hostile direct API and property tests |
| 5 — Isolated connector | Chosen mature transport, inner TLS, exact socket proxy, cancellation/leases | Q01 resolved; CONN/PROTO/SESSION tests in isolated lab |
| 6 — Linux/Arch client | Resource access, local key/IPC boundaries, package/service behavior | Real Linux/Arch tests and application workflows; no global route/DNS changes |
| 7 — Dashboard | Material Design 3, secure admin bridge/bootstrap, users/devices/resources/grants/connectors/audit/security | Q02 resolved, effective previews, accessibility/mobile/keyboard tests, no secret leakage |
| 8 — Windows | Required Windows client; connector next or shortly after MVP | Real CNG/ACL/service/suspend and parity tests |
| 9 — Android client | Required client, Kotlin platform integration, qualified app access | Real Keystore/lifecycle/Doze tests; honest Mullvad access-mode limits |
| 10 — Network hardening | Supported Compose deployment, LAN/Docker/IPv6/NAT profiles and safe rollout design | NET-01–08, including accidental publication and timed rollback |
| 11 — Mullvad/DNS | Isolated real Mullvad coexistence; default DNS invariance; qualified hostname mode | VPN/DNS evidence; optional split DNS stays absent until its tests pass |
| 12 — Optional SSH CA | Local SSH keys and narrowly authorized short-lived SSH certificates | Separate issuance/auth review; SSH authentication remains required |
| 13 — Update system | Signed distribution, version/capability visibility, staged install/rollback | UPDATE tests and real signing/recovery custody |
| 14 — Audit/hardening | Full acceptance suite and independent security review | Threat model matches implementation; all required gates pass; no unresolved critical/high findings |

Basic version visibility and authenticated MVP artifacts must arrive before any claimed supported distribution, even if automatic updating remains Phase 13. Phase numbers do not authorize releasing unsigned interim clients.

## Current work and next phase
The user authorized completion of all fifteen phases, including hosted CI and Linux execution. The controller domain is implemented and verified, with results in the [Phase 2 report](docs/phase-2-report.md). Q09 is resolved by [ADR-002](ADR-002-controller-storage.md). The development repository at lutralutraq77/Portico is public, and private vulnerability reporting is enabled. Release and deployment claims still require their full evidence.

Phase 3 includes strict PKI validation, durable enrollment/renewal, a restricted real issuer service, TLS-bound administrator/WebAuthn components and encrypted quarantined recovery. [ADR-004](ADR-004-restricted-issuer-admin-recovery.md) extends [ADR-003](ADR-003-pki-enrollment-boundary.md). Q02/Q03 remain open for physical keys and the actual browser/native origin binding; Q06 remains open for owner authentication and a physical finalization/recovery drill. Q08 has restricted adapter and bypass-test implementation, with custody, deployment and administrator renewal still unqualified. [ADR-005](ADR-005-resource-policy-boundary.md) adds online resource policy, immutable hardware-approved previews, private TLS APIs and audited schema 4 migration. Connector networking follows with the mature transport comparison and real socket enforcement. The 90 remaining acceptance cases stay visible until their full scenarios can execute.

## Future documentation mapping
| Required documentation area | Phase 0 source |
|---|---|
| docs/architecture.md, docs/api.md | ARCHITECTURE.md, PROTOCOL_DESIGN.md |
| docs/threat-model.md, security-model.md, trust-boundaries.md | THREAT_MODEL.md, SECURITY_INVARIANTS.md, TRUST_BOUNDARIES.md |
| docs/resource-model.md | RESOURCE_MODEL.md |
| docs/pki.md, enrollment.md | PKI_DESIGN.md |
| docs/revocation.md, sessions.md | SESSION_AND_REVOCATION_DESIGN.md |
| docs/recovery.md | BOOTSTRAP_AND_RECOVERY.md |
| docs/networking.md, mullvad.md, dns.md | NETWORK_AND_MULLVAD_DESIGN.md, DNS_DESIGN.md |
| docs/updates.md, audit.md | UPDATE_SECURITY.md, SECURITY_CONTROL_MATRIX.md |
| docs/development.md, testing.md | This roadmap, ACCEPTANCE_TEST_PLAN.md |
| docs/install/ubuntu-server.md, docker-compose.md | PLATFORM_SUPPORT.md and qualified network profile |
| docs/install/arch-linux-client.md, linux-client.md, windows-client.md | Platform matrix plus actual installers when implemented |
| docs/install/windows-connector.md, android-client.md | Real platform qualification and application flows |
| Optional docs/install/android-connector.md | Only if experimental connector is actually introduced |

## MVP versus production
The MVP must include Android and Windows clients, Linux connector, self-hosted controller, secure enrollment/admin factors, grants/revocation/expiry/audit, safe bootstrap/recovery, Material dashboard, Compose, version visibility and acceptance evidence. Windows connector may follow immediately; Android connector and integrated SSH CA are optional.

Production additionally requires proven LAN/Docker/IPv6 isolation, Mullvad/DNS compatibility, authenticated releases, tested rollback/recovery, dependency review and no open critical/high findings. Functional completeness alone is insufficient.

## Historical Phase 0 boundary
The user subsequently authorized Phase 1, then Phase 2, hosted development CI and Phase 3. The current objective extends development through all fifteen phases. These historical milestones do not narrow that objective or waive its platform, deployment, release and security evidence.
