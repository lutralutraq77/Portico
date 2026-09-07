# Hosted CI verification

Date: 2026-09-07. Repository: [lutralutraq77/Portico](https://github.com/lutralutraq77/Portico). Review: [PR #1](https://github.com/lutralutraq77/Portico/pull/1).

**All hosted checks passed for PR head d89bc40cac5b1b477bb9073ff82b9a7899d7e0b1.** These jobs executed GitHub's pull-request merge checkout. Phase 2 verification is complete.

| Check | Run | Result |
|---|---|---|
| Windows Server 2022 quality | [34139608641](https://github.com/lutralutraq77/Portico/actions/runs/34139608641) | Passed; job 101798380807 |
| Ubuntu 24.04 quality | [34139608641](https://github.com/lutralutraq77/Portico/actions/runs/34139608641) | Passed; job 101798381111 |
| CodeQL | [34139608643](https://github.com/lutralutraq77/Portico/actions/runs/34139608643) | Passed; results uploaded |
| Dependency review | [34139608595](https://github.com/lutralutraq77/Portico/actions/runs/34139608595) | Passed with the moderate-severity failure threshold |

Both quality jobs ran the full bootstrap/check commands: unit tests, race detection, CLI and destination fuzzing, formatting, vet, Staticcheck, dependency verification, application and development-tool vulnerability scans, scanner positive controls, workflow validation, builds and SBOM generation.

| Runtime measurement | Windows hosted | Ubuntu hosted |
|---|---|---|
| CLI statement coverage | 84.6% | 84.6% |
| Controller statement coverage | 76.4% | 76.2% |
| Five-second CLI fuzz executions | 195,989 | 185,424 |
| Five-second destination fuzz executions | 73,654 | 60,744 |
| Race detector | Passed | Passed |

Windows and Linux executable hashes match across the local Windows build and both hosted operating systems, using the same pinned SDK and build settings.

## Corrections verified by these runs

The jobs that previously failed before startup began executing on the 15:29 UTC retry. GitHub now reports the repository as public; the agent did not change its visibility or billing settings. The first real execution exposed these issues, which are now resolved:

- Windows Server 2022 tar lacked LZMA support. Bootstrap uses .NET ZIP extraction for Go and the checksum-verified compiler self-extractor. Quoting the compiler command also supports WorkRoot paths containing spaces; a fresh E: setup and race test verified this.
- The repository dependency graph was disabled. It is now enabled, allowing dependency review to execute.
- Development-tool archive and SSH dependencies required security updates: rardecode/v2 v2.2.5, ulikunitz/xz v0.5.15, klauspost/compress v1.18.7 and x/crypto v0.56.0 are pinned in tools/go.mod.
- Module-only vulnerability scanning did not inspect the tool-only module's declared programs. Bootstrap and vulnerability checks now enumerate the same five tools from go.mod. Package scanning covers their imported dependencies, and an isolated known-vulnerable fixture must detect GO-2025-4020.

Related advisories: [RAR dictionary limits](https://github.com/advisories/GHSA-rwvp-r38j-9rgg), [LZMA allocation](https://github.com/advisories/GHSA-jc7w-c686-c4v9), [compression bounds](https://pkg.go.dev/vuln/GO-2026-5841), [SSH established channels](https://pkg.go.dev/vuln/GO-2026-6355), [SSH undecided channels](https://pkg.go.dev/vuln/GO-2026-6354).

Govulncheck still lists GO-2026-5932 at module level for the unmaintained golang.org/x/crypto/openpgp package. No declared tool imports that package or its subpackages (verified against all 938 tool imports); the imported-package scan reports zero affected vulnerabilities. No advisory suppression was added.

## Retained evidence

Quality artifacts contain coverage, documentation results, redacted secret-scan evidence, the vulnerability positive control, SBOM and build hashes. Their downloaded ZIPs were verified against GitHub's artifact SHA-256 digests and saved with job logs under E:/Portico/work/reports/hosted-d89bc40.

| Artifact | ID | ZIP SHA-256 |
|---|---|---|
| quality-evidence-windows-2022 | 10025474417 | 1220c5aa700d6a095c310afbc9787edeed494a71754dded8efcf6f659016eba8 |
| quality-evidence-ubuntu-24.04 | 10025461513 | 4fac776970c55e61b3e0db07c6d0a57c1458e9a349c62d6d85d4b1521a4da009 |

GitHub repository metadata reported public visibility during final verification. Private vulnerability reporting was enabled and its saved state verified; response commitments remain owner governance work. No release, merge, deployment or production network change is part of this verification. AUDIT-01 has executable Windows/Linux evidence; the other 90 acceptance scenarios remain scheduled for later phases. See the [Phase 2 report](phase-2-report.md) for scope and limitations.
