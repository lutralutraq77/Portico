# Development environment

Phase 2 adds a local controller domain implementation to the tool/build environment. The executable has only help/version commands and no listener, route, DNS or credential behavior. Runtime network labs are deferred until the connector phase.

On this machine the project is E:\Portico. Portable Go, compiler, module/build caches, temporary files and reports live under its ignored work/ directory. Existing Git/PowerShell may be read from their installed locations; setup writes no global PATH, Go configuration or machine settings.

## Windows quick start
Run from the repository with PowerShell 7:

~~~powershell
./scripts/bootstrap.ps1
./scripts/check.ps1
./build/portico-windows-amd64.exe version --json
~~~

The bootstrap verifies pinned SDK/compiler archive SHA-256 values before extraction, downloads checksum-verified pinned Go tool modules, and builds the tools locally. It requires internet access only for initial downloads and vulnerability database checks. It does not install services or modify networking.

Windows SDK extraction uses .NET ZIP support, and the compiler uses its checksum-verified self-extractor in unattended mode. Neither depends on the host's tar codecs. WorkRoot paths containing spaces are supported.

Dot-source scripts/env.ps1 before manual Go commands so caches and temporary files remain on E:. GOTOOLCHAIN=local prevents unreviewed automatic toolchain downloads; GOENV=off avoids global Go config writes; Windows APPDATA/LOCALAPPDATA and platform configuration paths are redirected into work/ for these processes before go telemetry off configures telemetry. The check command verifies effective storage paths and telemetry state. A nested work/go.mod prevents Go from discovering SDK/cache sources as application packages.

## Linux/CI
Install the exact Go version in tools/toolchain.lock.json, Git, PowerShell 7, tar and a supported C compiler for race testing. Then run the same bootstrap/check scripts. GitHub CI pins setup-go and the SDK version. Linux hosted CI is configured; actual results are recorded in the Phase 2 report. Local Linux execution is available through scripts/test-linux.ps1.

A successful Windows-to-Linux cross-build is not a Linux runtime test. No Android support claim follows from this foundation.

## Direct checks
~~~powershell
. ./scripts/env.ps1
go test ./...
go test -race ./...
go vet ./...
./scripts/check-docs.ps1
./scripts/build.ps1
~~~

The complete check command additionally runs staticcheck, govulncheck, actionlint, redacted Gitleaks scanning, a synthetic secret-detection control and CycloneDX SBOM generation. See [testing](testing.md).

## Isolation and storage
A disposable Linux test VM with networking disabled is available. No multi-node network lab is provisioned yet. Tools work against repository source and synthetic local files only. Before Phase 5, provision disposable VMs/networks following [the lab plan](lab-plan.md); never reuse production Mullvad or firewall state.

work/ and build/ are disposable generated outputs, excluded from Git. Do not recursively delete them while tests/builds are running. Keys, certificates and production configuration do not belong there or in this repository.

The internal module path remains portico.local/portico. The development repository is private at lutralutraq77/Portico; licensing and any public module-path change remain separate decisions.
