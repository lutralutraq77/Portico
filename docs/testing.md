# Testing and evidence

Run scripts/check.ps1 for the complete repository check suite across the application and separate issuer modules. The tests verify the development CLI, controller domain and security transactions, real issuer integration, repository documentation consistency and quality-tool operation.

Foundation and domain checks:
- Unit tests reject unsupported commands and avoid reflecting secret-like arguments.
- JSON output explicitly identifies a Phase 6 development binary; output errors return failure.
- Bounded CLI fuzzing checks arbitrary command input.
- Race detector and go vet run against actual Go packages.
- Documentation checker validates required files, local links, references, the preserved brief and all 91 specified runtime case IDs and executable references for implemented cases.
- Adversarial checker fixtures deliberately break a link, reference, fence and runtime status; each must be rejected.
- Gitleaks scans source with redacted results; a separate generated synthetic token must trigger detection.
- Govulncheck scans the application and the imported packages of every declared development tool. A separate known-vulnerable dependency fixture must report GO-2025-4020; the fixture is never used by production or development tools.
- Windows/Linux cross-builds plus a native binary smoke test run. A second native build must be byte-identical with the same toolchain.
- Staticcheck, govulncheck, actionlint and CycloneDX SBOM generation run from pinned tool versions.
- Issuer SBOMs are generated separately from the Windows and Linux binaries, recording linked modules and verified binary SHA-256 hashes. Binary mode avoids recursively hashing the parent module's ignored caches through the local replacement. CycloneDX represents the local Portico component as `..`; adjacent Go build-metadata JSON verifies and retains its original module identity. Module verification and package vulnerability scans still cover the issuer dependency graph.

Reports are generated under work/reports. CI uploads only redacted JSON and coverage output, not keys, source caches or credentials. Tests use work/tmp and ephemeral loopback listeners for the real mutual-TLS issuer. Other runtime TLS tests use net.Pipe. External access is limited to dependency/tool/advisory downloads; runtime tests have no external service requirement.

SkipScanners or SkipRace are explicit convenience options and do not constitute a complete repository validation. Report skipped checks honestly.

Seven of the [91 runtime acceptance cases](../ACCEPTANCE_TEST_PLAN.md) have complete executable scenarios: AUDIT-01 process crashes, CONN-01 two-connector hosting/socket isolation, CONN-03 cross-connector control scope, CONN-04 active revocation/restart/replay, PROTO-03 independent stream lifecycles, PROTO-04 malformed inputs and actual HTTP/2 resets, and PROTO-05 backpressure/quotas/reconnects. The remaining 84 stay planned. The [isolation report](phase-5-isolation-report.md) [lifecycle report](phase-5-lifecycle-report.md) [overload report](phase-5-overload-report.md) and [hostile protocol report](phase-5-protocol-report.md) record exact runs; socket/process cases require separate guarded VM evidence. Linux-only process tests are excluded on Windows, and guest guards skip these scenarios on ordinary hosts. The manifest links implemented tests and is never a permanent passing report. Phase 3 adds X.509/TLS, durable enrollment/renewal, real step-ca/process/bypass tests, signed virtual WebAuthn assertions, atomic administrative mutation and anchored encrypted recovery tests; see [its integration report](phase-3-integration-report.md). Full browser/platform/physical issuer and administrator custody, policy, Docker, Mullvad and hardware-key scenarios remain pending.

The [Phase 2 report](phase-2-report.md) records what actually ran locally versus CI that is merely configured.

Run scripts/test-linux.ps1 on this Windows host for isolated Linux VM execution. The controller suite tests identity/reference mismatches, stale revisions, independent HostBindings, expiry, revocation metadata, atomic audit rollback, real SQLite page exhaustion, process crashes, sequence tampering, concurrent writes, restart closure and snapshot quarantine. Its partial coverage of later security scenarios does not replace end-to-end acceptance.
