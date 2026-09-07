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

Implementation revision `42bb1b9b59488157c0246083f3f12f17b5c4219d` passed the complete local Windows check suite without skip flags and the final isolated Linux VM run. Hosted Windows Server 2022 and Ubuntu 24.04 checks, CodeQL and dependency review also passed on that revision. [Machine-readable evidence](phase-3-integration-evidence.json) records measurements, build/SBOM hashes and local/hosted log hashes. The earlier foundation report describes a separate historical increment.

- The Linux VM passed 48 top-level tests, 132 subtests and 21 fuzz seeds on kernel 6.18.35-0-virt; its subprocess helper has one intentional skip outside child mode. This run used gRPC v1.83.1, guest loopback only, no NIC, and no host filesystem shares. VM race instrumentation was not used; native hosted Linux race tests passed separately.
- Windows and hosted checks passed unit, shuffled, race, bounded fuzz, vet, static analysis, vulnerability, secret, workflow and documentation checks. Both scanner positive controls detected their deliberately unsafe fixtures. Four Windows/Linux application and issuer binaries built, with byte-identical native rebuilds.
- Local coverage was 81.8% for administrator verification, 76.8% for the controller, 77.9% for the issuer adapter and 90.1% for PKI. The separate issuer service reached 77.7%; its command package reached 33.3%. These numbers describe exercised statements, not assurance of security completeness.
- Hosted runs: [Windows/Ubuntu quality](https://github.com/lutralutraq77/Portico/actions/runs/34155035446), [CodeQL](https://github.com/lutralutraq77/Portico/actions/runs/34155035518), [dependency review](https://github.com/lutralutraq77/Portico/actions/runs/34155035451).

Scans reported no reachable application vulnerabilities or imported issuer/tool package vulnerabilities. The unimported `golang.org/x/crypto/openpgp` module advisory GO-2026-5932 remains visible with no suppression. GitHub dependency review caught an additional gRPC advisory during development; the fixed v1.83.1 pin passed the final checks. The first module-based issuer SBOM run was stopped after it recursively hashed ignored parent-module caches. The final binary-based SBOM checks passed and verify the exact binary hashes and local-module provenance.

The dependency review selected age v1.3.2, go-webauthn v0.18.0 and go-jose v4.1.5. Smallstep's transitive gRPC, OpenTelemetry, pgx, JOSE v3, compression and x/crypto dependencies were updated to address scanner findings. The application module SBOM and separate Windows/Linux issuer binary SBOMs are generated; the latter include verified binary hashes and avoid recursively hashing development caches through the local module replacement. Test fixtures are cryptographically signed virtual authenticators, not evidence of hardware backing or two independently held devices.

The 91-scenario acceptance manifest remains honest: AUDIT-01 implemented; 90 planned. These additional component/integration tests do not satisfy the unexecuted full platform, browser, hardware, recovery, networking or data-plane scenarios.

## Remaining gates

Q02/Q03 need the intended private origin, browser/native transport design, OS key-provider integration, an actual UV-capable primary and independent backup key, vendor trust/status policy and hostile-origin/local-user qualification. Q08's restricted adapter has lab implementation and bypass tests; deployment network isolation, issuer custody/rotation and administrator renewal/replacement policy still need qualification.

Q06 needs authenticated local owner entry, independent recovery journal/material, bootstrap finalization and a physical recovery/restore drill. Recovery export is currently a trusted local primitive; remote export approval and restore unquarantine remain absent. No public reset or cookie-only fallback was introduced. Complete resource authorization and forwarding remain later phases.
