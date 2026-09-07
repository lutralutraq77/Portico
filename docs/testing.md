# Testing and evidence

Run scripts/check.ps1 for the complete repository check suite. The tests verify the development CLI, controller domain transactions, repository documentation consistency and quality-tool operation.

Foundation and domain checks:
- Unit tests reject unsupported commands and avoid reflecting secret-like arguments.
- JSON output explicitly identifies a Phase 2 development binary; output errors return failure.
- Bounded CLI fuzzing checks arbitrary command input.
- Race detector and go vet run against actual Go packages.
- Documentation checker validates required files, local links, references, the preserved brief and all 91 specified runtime case IDs and executable references for implemented cases.
- Adversarial checker fixtures deliberately break a link, reference, fence and runtime status; each must be rejected.
- Gitleaks scans source with redacted results; a separate generated synthetic token must trigger detection.
- Windows/Linux cross-builds plus a native binary smoke test run. A second native build must be byte-identical with the same toolchain.
- Staticcheck, govulncheck, actionlint and CycloneDX SBOM generation run from pinned tool versions.

Reports are generated under work/reports. CI uploads only redacted JSON and coverage output, not keys, source caches or credentials. Tests use work/tmp and do not access the real network except tool/advisory downloads.

SkipScanners or SkipRace are explicit convenience options and do not constitute a complete repository validation. Report skipped checks honestly.

AUDIT-01 among the [91 runtime acceptance cases](../ACCEPTANCE_TEST_PLAN.md) has a real process-crash test. The remaining 90 stay planned. The manifest links implemented tests and is never a permanent passing report. No certificate, policy, revocation, Docker, Mullvad or hardware-key behavior exists to test yet.

The [Phase 2 report](phase-2-report.md) records what actually ran locally versus CI that is merely configured.

Run scripts/test-linux.ps1 on this Windows host for isolated Linux VM execution. The controller suite tests identity/reference mismatches, stale revisions, independent HostBindings, expiry, revocation metadata, atomic audit rollback, real SQLite page exhaustion, process crashes, sequence tampering, concurrent writes, restart closure and snapshot quarantine. Its partial coverage of later security scenarios does not replace end-to-end acceptance.
