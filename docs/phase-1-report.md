# Phase 1 verification report

Status: **Phase 1 repository and quality foundation complete; all applicable local checks passed on 2026-09-07.** Hosted CI execution remains pending. Phase 2 has not started.

## Delivered scope

The foundation includes the Go repository, a development-only help/version CLI, pinned portable tools, formatting and lint checks, unit/race/fuzz tests, documentation validation, security scanners, SBOM generation, cross-platform build scripts, CI configuration, dependency policy and development/lab documentation.

The application uses only the Go standard library. Scanner dependencies are isolated in the separate tools module. No controller, authentication, enrollment, resource forwarding or network configuration behavior is implemented.

## Actual local verification

The complete command `./scripts/check.ps1` ran with neither skip option and exited successfully. Environment: Windows amd64, PowerShell 7.6.5, Go 1.27.1 and GCC 16.2.0 from the verified w64devkit 2.9.1 archive.

| Check | Observed result |
|---|---|
| Required design documents, links, references and preserved brief | Passed: 17 required documents, 57 Markdown documents; original brief SHA-256 unchanged |
| Documentation validator controls | Valid fixture accepted; four deliberately broken fixtures rejected |
| Formatting and module verification | Passed |
| Go vet and Staticcheck | Passed, no reported findings |
| Shuffled unit tests | Passed; CLI package statement coverage 84.6% |
| Race detector | Passed on Windows |
| Bounded CLI fuzzing | Passed: 75,546 executions, six baseline seeds, five-second fuzz budget |
| Windows and Linux amd64 builds | Both built successfully |
| Native Windows binary smoke test | Passed; version JSON explicitly reports development-only Phase 1 |
| Repeat native build | Windows output was byte-identical with the same toolchain and source |
| Application vulnerability scan | No vulnerabilities found by govulncheck |
| Development dependency module scan | No vulnerabilities found by govulncheck module scan |
| Source secret scan | No findings; separate synthetic positive control detected and redacted |
| Workflow validation | Actionlint passed; configured external action references use full commit hashes |
| Application CycloneDX SBOM | Generated; includes the Go standard library version |
| Storage and telemetry guard | Passed: caches, temporary storage and telemetry configuration resolve within the task work directory; telemetry is off |

The CLI unit tests cover rejected commands, non-reflection of sensitive-looking arguments, development version metadata and output failures. The command entrypoint has no direct unit test coverage; the actual binary is exercised by the smoke test. Coverage and fuzz counts describe this small foundation only.

Evidence is retained locally under `E:\Portico\work\reports`, including `phase1-complete-check.log`, `documentation.json`, `coverage.out`, `build-hashes.json`, `go-environment.json`, `gitleaks.json`, the redacted positive-control report and `sbom.cdx.json`. A repository snapshot is in [phase-1-evidence.json](phase-1-evidence.json). Results are a snapshot of this run, not a continuing guarantee.

## Built artifacts

These are unsigned development binaries, not supported releases.

| Artifact | SHA-256 |
|---|---|
| `build/portico-windows-amd64.exe` | `144653080DD44D54C067D1F46EA91BB17085A58B36DE7BD3426CB88C88EC94B6` |
| `build/portico-linux-amd64` | `10E84FA4B9046DE99C93D3242878170579465EAF7BA6D992643B557ED998E399` |

The repeat-build check establishes same-machine, same-toolchain determinism for Windows; it is not an independently reproduced release build.

## Storage and development isolation

The project is at `E:\Portico`. Tool archives, extracted toolchains, module/build caches, generated tools, temporary fixtures and reports use its ignored `work/` directory; binaries use `build/`. The environment script changes only the current process and rejects a Windows work directory on C:.

A nested scratch module keeps Go package discovery out of toolchains, caches and research files. Windows APPDATA/LOCALAPPDATA and platform configuration paths are redirected for these development processes before `go telemetry off` runs. The checker verifies the effective Go paths and telemetry state rather than relying on an ignored environment-variable setting.

No services, production listeners, firewall rules, routes, DNS configuration or Mullvad settings were changed. The isolated network lab is documented for later implementation.

## Pending evidence and decisions

- Windows/Linux quality CI, CodeQL, dependency review and Dependabot are configured and locally syntax-checked. No hosted runs, remote branch protection or repository publication occurred.
- Linux was cross-compiled; Linux native execution, Android behavior and real deployment environments were not tested.
- All **91 runtime acceptance cases remain planned, with zero implemented**. Certificate authentication, authorization, revocation, recovery, resource isolation, Docker, IPv6 and Mullvad acceptance have not run.
- Git is initialized on main with no commits or remote. The SBOM generator consequently warns that the main module version cannot be derived from Git. The SBOM includes `std@go1.27.1`; application release version/provenance must be established before distribution.
- SQLite driver selection (Q09) is explicitly deferred to the beginning of Phase 2, before durable state implementation. Phase 1 deliberately adds no unused runtime dependency.
- Repository ownership and licensing (Q13), and the other [open design gates](../OPEN_QUESTIONS.md), remain unresolved. No license compatibility or production-readiness claim is made.

## Reproduce and continue

Run from `E:\Portico` in PowerShell 7:

~~~powershell
./scripts/bootstrap.ps1
./scripts/check.ps1
./build/portico-windows-amd64.exe version --json
~~~

Bootstrap and advisory checks require internet access. See [development](development.md), [testing](testing.md) and [dependency policy](dependency-policy.md).

The next application phase is the controller domain model and its tests. Resolve the storage gate before durable state, and preserve the no-real-network boundary in [the roadmap](../ROADMAP.md). This task stops at Phase 1.

