# Linux runtime test harness

The harness runs on Windows or Linux and boots a real Linux amd64 kernel under QEMU TCG, with no network devices or host filesystem shares. Its disposable initramfs contains CLI/domain/PKI/WebAuthn/control-JSON/carrier/control-client/boot-clock/clock-health/workload/connector/local-file/issuer test binaries and a tiny Go PID 1. Guest loopback and a fixture localhost hosts file support actual issuer TLS/process, carrier TLS/gRPC and controller HTTP client tests; neither affects the host. The workload fixture adds 192.0.2.10/32 to guest loopback for an exact destination TCP test without relaxing production destination checks. SQLite, issuer databases and temporary fixture keys live in guest memory. This verifies Linux execution and process-crash behavior; it is not an Ubuntu installation, Linux race run or hardware power-loss test.

PID 1 explicitly protects the guest root directory with mode 0755; the temporary root filesystem otherwise starts at 01777 and correctly fails production path-ownership checks. Native clock-provider tests are read-only. A separate, guarded connector process test supplies and restores synthetic synchronization metadata in this disposable kernel to exercise the real command; it does not change UTC or the host clock and makes no upstream synchronization claim. [Connector command evidence](phase-5-connector-command-report.md).

Run ./scripts/test-linux.ps1 after preparing the local assets. Results are recorded in work/reports/linux-runtime.log. The harness requires a final PORTICO_LINUX_ALL_PASS marker and rejects test failures.

For focused development, ./scripts/test-linux.ps1 -WorkloadOnly records work/reports/linux-workload-runtime.log and requires the distinct PORTICO_LINUX_WORKLOAD_PASS marker. That mode runs clock/workload unit tests and the guest destination integration group; it does not qualify the complete suite. The complete controller binary has a 600-second harness timeout after a measured full-suite run exceeded the prior 300-second limit. This test-process limit does not change any connection lease, activation or closure deadline.

## Pinned assets

The exact URLs, versions and hashes are in tools/linuxvm/assets.lock.json.

- QEMU 11.1.0 Windows build from the distributor linked by the [QEMU project](https://www.qemu.org/download/).
- Alpine 3.24.1 virtual ISO and its published SHA-256 from [Alpine downloads](https://www.alpinelinux.org/downloads/); extract boot/vmlinuz-virt.
- 7-Zip 26.03 MSI from the [official release](https://github.com/ip7z/7zip/releases/tag/26.03), verified against the release asset digest, used only as an archive source.

On this machine the files are under E:/Portico/work. QEMU's installer payload was extracted as an archive; no QEMU service or machine installation was performed. The 7-Zip cabinet was read through the Windows MSI database API in read-only mode and extracted with Windows expand.exe; its installer was not run.

Put the extracted QEMU files under work/toolchains/qemu and the verified kernel under work/linux/boot/vmlinuz-virt. The test script checks the kernel hash before boot. The host only passes explicit test artifacts through the initramfs, and captures serial output in work/reports.

Checksums establish integrity relative to upstream metadata fetched over HTTPS. They are not a claim that the VM toolchain has received an independent security audit.

## Hosted Linux testing

The GitHub quality matrix separately runs the full check.ps1 script on Ubuntu and Windows. That includes native builds and race testing. These native runs skip destination scenarios unless the guarded disposable guest is present.

The Isolated Linux runtime workflow builds the pinned Linux QEMU source with additional downloads disabled, extracts the same pinned guest kernel, and invokes the complete test-linux.ps1 harness on an Ubuntu build host. QEMU still uses TCG, two virtual CPUs, no NIC, and no host filesystem shares. The Linux build is installed only inside the workspace; the prerequisite packages are installed on the ephemeral hosted runner. scripts/prepare-linux-runtime.ps1 can prepare the same assets on an x64 Linux build host with the documented workflow prerequisites.

The Linux source pin is QEMU 11.1.1. Its detached signature was verified against the release signer fingerprint CEACC9E15534EBABB82D3FA03353C9CEF108B584 published by the [QEMU project](https://www.qemu.org/download/), before recording its SHA-256 in tools/linuxvm/assets.lock.json. The preparation script checks that pinned digest on every use. Windows retains its separately pinned 11.1.0 build. Both paths verify the emulator version and guest kernel before execution. linux-runtime-environment.json records the actual emulator and initramfs hashes and the isolation settings alongside the complete guest log.

Successful complete hosted guest runs and their source/artifact provenance are recorded in the [ordinary enrollment report](phase-6-enrollment-report.md) and [durable-state record](local-state.md). Later changes still require their own qualification. Local diagnostic runs have exposed setup deadline failures and a native clock sample exceeding the workload's 100 ms limit; the production clock latch, leases, revocation checks and guest guards remain unchanged. A complete guest pass is still separate from supported OS installation, real time-service, physical suspend and hardware qualification.

The enrollment package's test-process budget is 600 seconds to accommodate sequential password KDF tests at the production work factor and separate enrollment CLI processes under emulation. This does not change the five-second HTTP/TLS deadlines or any runtime authority limit.
