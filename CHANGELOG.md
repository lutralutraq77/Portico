# Changelog

## Unreleased — Phase 2
- Added transactional SQLite controller domain state, exact resource revisions and independent device/host permissions.
- Added certificate metadata, requested session lifecycle, immutable audit outbox and quarantined snapshots.
- Added adversarial domain tests, process-crash atomicity, real SQLITE_FULL failure, audit tamper detection and Linux VM execution.
- Created private hosted development repository and prepared hosted quality runs.
- Authenticated APIs, PKI issuance and network forwarding remain later phases.

## Phase 1 — Development foundation
- Added local Git repository, version-only Go command and process-local development setup.
- Pinned Go 1.27.1, development scanner modules/checksums, compiler archive and CI action commits.
- Added unit/fuzz/race/build checks, documentation consistency tests, secret scanner positive control and SBOM generation.
- Configured Windows/Linux quality jobs, CodeQL, dependency review and Dependabot.
- Added required documentation entry points and machine-readable runtime acceptance backlog.
- No controller, issuer, resource proxy, enrollment, dashboard or production networking is implemented.

## Phase 0 — 7 September 2026
- Created researched design package, invariants, threat/control registers and 91 planned acceptance cases.
