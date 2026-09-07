# Phase 3 issuer, administrator and recovery integration

Phase 3 remains in progress. This increment implements the real issuer service, administrator server components and encrypted recovery primitives. The owner is undecided on primary/backup hardware-key models and the private sign-in hostname. No physical hardware, production origin, deployed issuer or completed recovery ceremony is claimed.

## Implemented

- Separate restricted issuer executable using Smallstep certificates v0.30.2; ES256 controller adapter; pinned mutual TLS; one fixed profile/issuer per durable database; CSR-bound short-lived tokens; exact approved identities and validity; no stock renewal/rekey/ACME/SSH endpoints.
- Durable single-use token hashes and public issuance receipts. Explicit local result retrieval supports controller reconciliation without re-signing. Actual step-ca tests cover three profiles, direct bypass attempts, restart replay, controller enrollment and a separate issuer process.
- Separate administrator certificate profile, pinned issuer and live registry. Ordinary certificates cannot become administrator credentials. Administrative server operations require real TLS key possession and a current owner/device.
- go-webauthn registration and assertion verification with required user verification, packed attestation, reviewed local root/AAGUID policy and rejection of synced/backup-eligible credentials. Policy expiry, origin/RP changes, bad signatures, missing presence/verification and counter warnings reject.
- Audited schema 3 migration from known schema 1/2, with rollback on failure. Immutable operations and one-use challenges bind administrator, certificate, exact change, policy generation and expiry. Factor counters, approved mutation and audit commit atomically. Implemented flows include invitation, factor testing, backup-factor retirement of a lost key and approved replacement registration.
- age-encrypted, bounded, consistent recovery snapshots with an independently retained ciphertext/audit anchor. Restores disable copied credentials, remove challenges and remain quarantined. Wrong keys, modifications, truncation, trailing bytes, wrong checkpoints, overwrite attempts and valid re-encryption without a matching trusted anchor reject.

See [ADR-004](../ADR-004-restricted-issuer-admin-recovery.md) for threat boundaries and [issuer operation](issuer.md) for the runnable command and configuration contract. All local source, caches, build files and test artifacts stay on E:. Test host listeners are ephemeral loopback TLS; VM listeners are guest loopback with no NIC or filesystem shares.

## Verification

Focused Windows cryptographic, transaction, recovery and real-issuer tests pass. Complete Windows checks, expanded Linux VM execution and exact-head hosted CI are being run; final evidence will be recorded here and in a machine-readable report after they finish. No previous commit's CI result substitutes for this increment's tests.

The dependency review selected age v1.3.2, go-webauthn v0.18.0 and go-jose v4.1.5. Smallstep's transitive gRPC, OpenTelemetry, pgx, JOSE v3, compression and x/crypto dependencies were updated to address scanner findings. The application module SBOM and separate Windows/Linux issuer binary SBOMs are generated; the latter include verified binary hashes and avoid recursively hashing development caches through the local module replacement. Test fixtures are cryptographically signed virtual authenticators, not evidence of hardware backing or two independently held devices.

The 91-scenario acceptance manifest remains honest: AUDIT-01 implemented; 90 planned. These additional component/integration tests do not satisfy the unexecuted full platform, browser, hardware, recovery, networking or data-plane scenarios.

## Remaining gates

Q02/Q03 need the intended private origin, browser/native transport design, OS key-provider integration, an actual UV-capable primary and independent backup key, vendor trust/status policy and hostile-origin/local-user qualification. Q08's restricted adapter has lab implementation and bypass tests; deployment network isolation, issuer custody/rotation and administrator renewal/replacement policy still need qualification.

Q06 needs authenticated local owner entry, independent recovery journal/material, bootstrap finalization and a physical recovery/restore drill. Recovery export is currently a trusted local primitive; remote export approval and restore unquarantine remain absent. No public reset or cookie-only fallback was introduced. Complete resource authorization and forwarding remain later phases.
