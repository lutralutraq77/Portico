# Update and release security

Status: Phase 0 design. There is no installer, updater, release or signing infrastructure yet.

## Threat and trust model
A malicious mirror, DNS response, repository account, old signed artifact or compromised online signing key must not silently replace the software. Release-signing trust is independent of device/admin CA trust.

Recommend The Update Framework (TUF) metadata and a maintained verifier implementation. TUF provides roles and validation rules addressing rollback/freeze and repository compromise; Portico must still implement safe installation and protect local trust state. [TUF specification](https://theupdateframework.github.io/specification/latest/).

Proposed root custody: 2-of-3 offline release root keys held independently, distinct delegated targets/signing roles and short-lived online freshness metadata. Q10 must establish actual maintainers, quorum availability, expiry policies and recovery before public releases. Do not invent maintainers or label an unsigned artifact trusted.

## Update state machine
Available → Downloaded → Verified → Staged → Owner-approved installation → Restarted → Health-verified → Committed.
Any step may fail; failed verification never reaches staging/installation.

Verify signed root chain, role thresholds, metadata versions/expiry, target hash/length, platform/architecture, compatibility and minimum security version. Reject replayed, expired, truncated, mismatched or unknown targets. HTTPS is useful transport, not release authenticity. Persist highest trusted metadata versions outside replaceable binary slots.

No blind “latest.” Compose uses exact version/digest after authenticity verification; a digest alone does not identify the author. Windows signed packages and Android package signing supplement the common release trust plan. Android package-key continuity and offline distribution are explicit platform requirements.

Owner approval is required for an update that could affect access unless they deliberately enabled a policy for it. Update available, download, verification, install, restart and rollback remain separate UI states. Version visibility belongs in MVP even while automatic updating is deferred.

## Rollback
Keep known-good binary/image slot and snapshot compatible configuration/schema before mutation. Validate migration on a copy; quiesce writes where required. Record rollback compatibility before installing. Irreversible migrations cannot promise automatic binary rollback.

Rollback selects a still-authentic, compatible build above the current security floor. It must not restore old device revocations, consumed tokens, active sessions, trust metadata or security settings merely to make an old binary start. If safe binary rollback cannot interpret current state, quarantine and use a documented migration/recovery path.

Test a simulated bad release that breaks management access: health verification must prevent committing it, while local console remains available. Health means certificate enrollment/administration and resource authorization checks, not just an HTTP 200.

## Offline operation
Running installed software does not require a SaaS account or daily external connectivity. Offline update imports carry signed metadata and artifacts; verification uses retained trusted roots and reliable time. Expired freshness metadata blocks a new update, not ordinary resource access. Do not bypass expiry because the owner is offline; obtain fresh valid metadata or use a documented release-root recovery ceremony.

Trust-root compromise cannot be repaired solely through a channel authenticated by that compromised root. Establish replacement trust independently. Loss of online signing keys is handled by offline root/delegation revocation. Loss of sufficient offline root keys may require out-of-band trust replacement.

## Supply-chain foundation for Phase 1
After authorization, pin toolchains, dependencies and CI actions by reviewed versions/immutable commits. Require formatting/linting, unit/security tests, dependency review, secret scanning, vulnerability scanning, license review and SBOM generation. Go race detector/fuzzing/static analysis and govulncheck are candidate tools; selection/version pinning happens during Phase 1. [Go security tooling](https://go.dev/doc/security/).

Use least-privilege CI, read-only permissions by default, no production secrets in PR jobs, and no untrusted PR execution with signing credentials. Review binary provenance and maintain isolated release jobs. Signed attestations supplement artifact verification; they are not proof that source is safe.

Define a vulnerability intake before publication, with private reporting and no demand for public exploit disclosure. Proposed response objectives: acknowledge within 3 business days, triage critical/high promptly, publish a remediation/advisory plan when verified. These are future maintainer commitments needing agreement, not an existing support SLA.

## Proof
UPDATE-01–06 cover forged/replayed metadata, rollback/freeze, offline expiry, bad restart, schema incompatibility and compromised key rotation. AUDIT-04 covers release audit. CTRL-15/16 cover trusted components, failure and recovery.
