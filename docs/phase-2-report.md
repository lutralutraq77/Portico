# Phase 2 implementation and verification

Status: **Phase 2 controller domain foundation and verification complete on 2026-09-07.** Local Windows, isolated Linux, hosted Windows/Ubuntu, CodeQL and dependency review all passed. Phase 3 has not started. Exact hosted commits, jobs and retained artifacts are in [the execution record](hosted-ci.md).

The hosted retry exposed Windows extraction portability and development-tool vulnerability-scan gaps. These were corrected, affected dependencies were patched, and the complete checks passed again. Current documentation describes Phase 2; the Phase 1 report remains a historical snapshot.

## Delivered

SQLite-backed users, devices, connectors, issuer/certificate metadata, resource revisions, explicit device grants, independent HostBindings, requested session records and an immutable audit outbox now exist in internal/controller. Mutations and their audit events commit together; revision checks prevent stale edits. Resource revisions invalidate previous permissions. Sessions cannot enter an authorized or active state in Phase 2.

The storage gate is resolved by [ADR-002](../ADR-002-controller-storage.md). The controller methods are trusted local operations, not authenticated API handlers. TLS proof, hardware approval, certificate issuance and real network forwarding remain later work.

## Actual results

The full ./scripts/check.ps1 command ran with no skip flags and passed. ./scripts/test-linux.ps1 also passed on a real Linux kernel under isolated QEMU emulation.

| Check | Result |
|---|---|
| Windows unit tests | Passed; CLI statement coverage 84.6%, controller 76.4% |
| Windows race detector | Passed |
| CLI fuzzing | Passed: 204,152 executions in a five-second budget |
| Destination fuzzing | Passed: 47,192 executions in a five-second budget |
| Go formatting, vet and Staticcheck | Passed |
| Module checksums | Verified |
| Application and development-tool package govulncheck | No affected vulnerabilities; known-advisory detection control passed |
| Gitleaks source scan | No secrets found; separate synthetic positive control detected and redacted |
| Workflow syntax | Actionlint passed |
| Required documentation and acceptance manifest | Passed: 17 required design documents, 91 case IDs |
| Windows/Linux amd64 builds | Passed; repeated native Windows build byte-identical |
| CycloneDX application SBOM | Generated, including runtime dependencies and standard library |
| Linux execution | Passed: 17 top-level tests, 27 subtests, 11 fuzz seeds and CLI smoke test |
| Linux environment | Kernel 6.18.35-0-virt from Alpine 3.24.1; QEMU 11.1.0 TCG; amd64; guest tmpfs |
| Development storage | Project, tools, caches, temporary files and reports under E:/Portico; process-local Go telemetry disabled |
| Hosted Windows/Ubuntu quality | Both passed the complete suite, including runtime and race tests |
| CodeQL and dependency review | Passed for PR head d89bc40cac5b1b477bb9073ff82b9a7899d7e0b1 |
| Fresh Windows bootstrap | Passed under an E: path containing spaces; extracted compiler passed a race test |

The isolated Linux execution uses cross-compiled test binaries on a real kernel. The VM has no network adapter or host filesystem share. Separate hosted Ubuntu runtime and race checks also passed. The command entrypoint has no direct unit coverage and is exercised by native binary smoke tests.

Development-tool scanning now checks every declared tool's imported packages. Earlier module-only scan output did not establish that coverage. The current scanner still identifies an unimported legacy OpenPGP package at module level; see the hosted record for the verified import boundary. No advisory was suppressed.

## Security acceptance progress

**AUDIT-01 is now implemented and passed on Windows and Linux.** Subprocesses terminate after a state write, after its audit append and after commit. Reopening verifies that state/audit are both absent or both present. This tests process crashes, not physical power loss.

The remaining **90 cases stay planned**. Domain tests provide partial evidence for audit continuity, error redaction, storage failure and permission semantics without claiming later end-to-end scenarios pass.

Additional adversarial checks cover mismatched identities/references, disabled entities, expired authority, stale resource revisions, independent hosting permissions, non-inheritance by future devices, terminal sessions, restart invalidation, duplicate concurrent writes, poisoned transactions, audit gap/tamper detection and unknown/corrupt schemas. A real SQLite page-count ceiling triggers SQLITE_FULL and proves transaction rollback. Snapshot tests prove source consistency, exclusive publication and quarantine on reopen.

## Evidence and reproduction

The machine-readable [evidence snapshot](phase-2-evidence.json) records local and hosted results and hashes. Full logs, coverage, SBOM and build hashes are under work/reports on E:. The latest local full-check log is phase2-ci-fixes-check.log; downloaded hosted artifacts and job logs are retained under work/reports/hosted-d89bc40.

~~~powershell
./scripts/bootstrap.ps1
./scripts/check.ps1
./scripts/test-linux.ps1
~~~

See [Linux harness setup](linux-runtime.md) for the pinned VM assets. No Windows optional Linux feature or QEMU service was installed. The version-only executable reports 0.2.0-dev.

## Boundaries

The database and snapshot primitive contain plaintext metadata and require appropriate filesystem ownership/ACLs and deployment disk encryption. Snapshot quarantine is not the encrypted recovery ceremony. EmergencyDeny is process-local containment, not durable remote revocation. An audit hash chain cannot stop root rewriting local history and its head.

No production ports, routes, DNS, firewall or Mullvad settings were changed. No private device keys, real users, production policy or live resources were created. The GitHub development repository is now public, with private vulnerability reporting enabled; licensing, production deployment, signing custody and further application phases remain separate decisions.

This report records the verified implementation snapshot. Use the repository's Actions results for checks on subsequent documentation commits and exact commit attribution.
