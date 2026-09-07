# Phase 3 progress: PKI and enrollment foundation

Phase 3 is in progress. The first component implementation is complete; the administrator, real issuer and recovery gates below remain open. Phase 2 was merged through [PR #1](https://github.com/lutralutraq77/Portico/pull/1) at commit 15114a423d4cf30d0da7cc9e8ade9d152eaa485f before this branch was created.

## Implemented

- Strict CSR and certificate profiles using Go X.509; pinned deployment/root/issuer; exact identity, key usage, SAN, signature, key type and time checks. Raw CSR attributes and SAN forms silently omitted by convenience parsers are also checked.
- SQLite schema version 2 with a validated, audited version 1 migration. Public trust bindings are immutable configuration; administrator profiles reject.
- Hashed single-use invitations, permanent attempt/key reservations, one provider invocation, independently validated issuer output, public-result recovery and explicit revocation.
- TLS 1.3 possession proof, pending enrollment activation, live registry checks, no session tickets, expiry/issuer/user/device/leaf/storage/emergency denial.
- Ordinary same-key renewal within existing authority. New credential activation atomically revokes the old credential; revoked sources cannot activate pending renewals.
- Quarantined snapshots revoke copied enrollments. The application CLI reports 0.3.0-dev and still exposes only help/version.

The [PKI decision](../ADR-003-pki-enrollment-boundary.md) records the exact implementation boundary and supporting upstream sources. Invite, BindIssuer and reconciliation are trusted local operations; none is an authenticated administrator endpoint. The executable has no issuer provider. The only signer is test code using real ephemeral X.509 keys.

## Verification

Focused Windows tests have passed for strict profiles/CSRs, real TLS positive and negative handshakes, concurrent redemption, provider constraint changes, uncertain issuance/restart reconciliation, actual process exit inside the issuance provider, renewal, live revocation, schema migration, audit rollback and snapshot quarantine. TLS runs over in-memory net.Pipe connections, with both peers performing actual certificate/signature verification; it opens no host listening port.

Implementation commit 2aedf7cb329449ed7bef1104f72f97b119f80bb6 passed the complete local check.ps1 suite with no skips, the isolated Linux VM, and all hosted checks. The [machine-readable evidence](phase-3-evidence.json) records commit, runs, measurements and log hashes.

| Environment/check | Result |
|---|---|
| Local Windows | Unit, race, fuzz, vet, Staticcheck, module verification, vulnerability/secret scans and positive controls, documentation/workflow checks, builds and SBOM passed |
| Isolated Linux kernel 6.18.35-0-virt / QEMU TCG | 35 top-level tests, 76 subtests and 16 fuzz seeds passed; no network devices or host filesystem shares |
| Hosted Windows Server 2022 and Ubuntu 24.04 | Full [quality run 34149427817](https://github.com/lutralutraq77/Portico/actions/runs/34149427817) passed, including native race tests on both systems |
| CodeQL | [Run 34149427803](https://github.com/lutralutraq77/Portico/actions/runs/34149427803) passed |
| Dependency review | [Run 34149427808](https://github.com/lutralutraq77/Portico/actions/runs/34149427808) passed; no new module dependencies |

Local coverage was CLI 84.6%, controller 76.5% and PKI 90.1%. Five-second bounded fuzz runs executed 77,934 CLI, 10,959 destination and 39,790 PKI cases; these counts are executions, not unique security acceptance scenarios. The final Linux run includes migration data-preservation and audit-failure rollback tests. TLS/X.509 code was also updated to use supported Go APIs after Staticcheck flagged deprecated coordinate/attribute access.

Application and imported development-tool package vulnerability checks passed. The previously documented unimported legacy OpenPGP module advisory remains visible; it is not suppressed or introduced by this change. Both scanner positive controls detected their intentionally unsafe fixtures.

Reports and all local tool/cache/test storage remain under E:/Portico/work. Full logs are phase3-check.log, linux-runtime.log and phase3-hosted-{windows,ubuntu}.log under work/reports. No machine routes, firewall, DNS, Mullvad or global trust configuration are changed. This evidence covers the implementation commit; GitHub checks on later documentation commits are displayed on [PR #2](https://github.com/lutralutraq77/Portico/pull/2).

The canonical acceptance manifest still contains 91 cases: AUDIT-01 implemented; 90 planned. The new tests provide component coverage of AUTH/PKI/REC requirements, but do not claim the full issuer, platform, admin, recovery or data-plane scenarios passed.

## Remaining Phase 3 work

1. Q08: reviewed step-ca integration and direct signing/provisioner/renewal bypass tests. Its exact issuance template must match the pinned validator profile; client-supplied claims cannot select identities or authority.
2. Q02/Q03: stable private sign-in origin, native device binding, actual primary and backup hardware-key models, attestation policy and real user-verification tests. Administrator enrollment and renewal remain disabled.
3. Platform key providers, fresh operation-bound WebAuthn approval and administrator lifetime policy, with real hardware and hostile-origin testing.
4. Q06: local owner authentication, recoverable bootstrap, encrypted backups and a real restore/finalization drill. Planned certificate overlap and compromise replacement also remain to be qualified.

These gates prevent Phase 3 completion and deployment claims. Resource policy and connector networking remain the following phases.
