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

Full local quality, isolated Linux and current-branch hosted CI results will be recorded after their runs complete. Reports and all local tool/cache/test storage remain under E:/Portico/work. No machine routes, firewall, DNS, Mullvad or global trust configuration are changed.

The canonical acceptance manifest still contains 91 cases: AUDIT-01 implemented; 90 planned. The new tests provide component coverage of AUTH/PKI/REC requirements, but do not claim the full issuer, platform, admin, recovery or data-plane scenarios passed.

## Remaining Phase 3 work

1. Q08: reviewed step-ca integration and direct signing/provisioner/renewal bypass tests. Its exact issuance template must match the pinned validator profile; client-supplied claims cannot select identities or authority.
2. Q02/Q03: stable private sign-in origin, native device binding, actual primary and backup hardware-key models, attestation policy and real user-verification tests. Administrator enrollment and renewal remain disabled.
3. Platform key providers, fresh operation-bound WebAuthn approval and administrator lifetime policy, with real hardware and hostile-origin testing.
4. Q06: local owner authentication, recoverable bootstrap, encrypted backups and a real restore/finalization drill. Planned certificate overlap and compromise replacement also remain to be qualified.

These gates prevent Phase 3 completion and deployment claims. Resource policy and connector networking remain the following phases.
