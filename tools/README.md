# Pinned development tools

This separate Go module keeps scanner/build-tool dependencies out of the Portico runtime module.
Tool directives, exact versions and checksums are committed in go.mod/go.sum here.
The application currently has **no third-party Go dependencies**.

Install/build with [the development setup script](../scripts/bootstrap.ps1).
Run the quality gates with [check.ps1](../scripts/check.ps1).

The SDK/compiler archives are independently pinned in toolchain.lock.json. Downloads are verified before extraction. Developer caches and reports live under work/; never commit them. Updating tools requires review and a successful complete check run.
