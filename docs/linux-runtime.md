# Linux runtime test harness

The Windows-hosted harness boots a real Linux amd64 kernel under QEMU TCG, with no network devices or host filesystem shares. Its disposable initramfs contains CLI/domain/PKI/WebAuthn/control-JSON/carrier/control-client/issuer test binaries and a tiny Go PID 1. Guest loopback and a fixture localhost hosts file support actual issuer TLS/process, carrier TLS/gRPC and controller HTTP client tests; neither affects the host. SQLite, issuer databases and temporary encrypted fixture keys live in guest tmpfs. This verifies Linux execution and process-crash behavior; it is not an Ubuntu installation, Linux race run or hardware power-loss test.

Run ./scripts/test-linux.ps1 after preparing the local assets. Results are recorded in work/reports/linux-runtime.log. The harness requires a final PORTICO_LINUX_ALL_PASS marker and rejects test failures.

## Pinned assets

The exact URLs, versions and hashes are in tools/linuxvm/assets.lock.json.

- QEMU 11.1.0 Windows build from the distributor linked by the [QEMU project](https://www.qemu.org/download/).
- Alpine 3.24.1 virtual ISO and its published SHA-256 from [Alpine downloads](https://www.alpinelinux.org/downloads/); extract boot/vmlinuz-virt.
- 7-Zip 26.03 MSI from the [official release](https://github.com/ip7z/7zip/releases/tag/26.03), verified against the release asset digest, used only as an archive source.

On this machine the files are under E:/Portico/work. QEMU's installer payload was extracted as an archive; no QEMU service or machine installation was performed. The 7-Zip cabinet was read through the Windows MSI database API in read-only mode and extracted with Windows expand.exe; its installer was not run.

Put the extracted QEMU files under work/toolchains/qemu and the verified kernel under work/linux/boot/vmlinuz-virt. The test script checks the kernel hash before boot. The host only passes explicit test artifacts through the initramfs, and captures serial output in work/reports.

Checksums establish integrity relative to upstream metadata fetched over HTTPS. They are not a claim that the VM toolchain has received an independent security audit.

## Hosted Linux testing

The GitHub quality matrix separately runs the full check.ps1 script on Ubuntu and Windows. That includes native builds and race testing. A successful QEMU run is useful local evidence while hosted execution is pending; retain the hosted run URL separately once it exists.
