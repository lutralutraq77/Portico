param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if (-not $IsLinux) { throw 'Prepare and run the Arch systemd fixture on a Linux Docker build host' }
$revision = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') { throw 'Missing source revision' }
$dirty = @(& git status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Systemd qualification requires a clean checkout' }
$packageRoot = Join-Path $PorticoWork ('arch-package/' + $revision)
$provenance = Get-Content -Raw -LiteralPath (Join-Path $packageRoot 'provenance.json') | ConvertFrom-Json
$qualification = Get-Content -Raw -LiteralPath (Join-Path $packageRoot 'qualification.json') | ConvertFrom-Json
if ($provenance.source_revision -ne $revision -or $qualification.source_revision -ne $revision) { throw 'Package source mismatch' }
$package = Join-Path $packageRoot ('output/' + $qualification.package)
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $qualification.package_sha256) { throw 'Package checksum mismatch' }
$imageLock = Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/arch-package.lock.json') | ConvertFrom-Json
if ($imageLock.image -ne $qualification.image -or $imageLock.image -notmatch '^quay\.io/archlinux/archlinux@sha256:[0-9a-f]{64}$' -or $imageLock.platform -ne 'linux/amd64') { throw 'Arch image mismatch' }
$runtimeLock = Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/linuxvm/assets.lock.json') | ConvertFrom-Json
$qemu = Join-Path $PorticoWork 'toolchains/qemu-linux/bin/qemu-system-x86_64'
$kernel = Join-Path $PorticoWork 'linux/boot/vmlinuz-virt'
$qemuVersion = (& $qemu --version | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or $qemuVersion -notmatch ('^QEMU emulator version ' + [regex]::Escape($runtimeLock.linux_qemu.version) + '(\s|$)')) { throw 'Unqualified QEMU version' }
if ((Get-FileHash -LiteralPath $kernel -Algorithm SHA256).Hash -ine $runtimeLock.kernel_sha256) { throw 'Kernel checksum mismatch' }
$root = Join-Path $PorticoWork ('arch-systemd/' + $revision)
if (Test-Path -LiteralPath $root) { throw 'Systemd output already exists; preserve its evidence' }
[IO.Directory]::CreateDirectory($root) | Out-Null
$priorOS=$env:GOOS; $priorArch=$env:GOARCH; $priorCGO=$env:CGO_ENABLED
try {
    $env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    & go test -c -o (Join-Path $root 'controller') ./internal/controller
    if ($LASTEXITCODE -ne 0) { throw 'Service enrollment/resource test build failed' }
} finally { $env:GOOS=$priorOS; $env:GOARCH=$priorArch; $env:CGO_ENABLED=$priorCGO }
$driver = Join-Path $PSScriptRoot 'arch-systemd-rootfs.sh'
$dockerArgs = @('run','--rm','--pull=never','--platform',$imageLock.platform,'--network=none','--security-opt=no-new-privileges','--env','LC_ALL=C','--env',('PORTICO_BINARY_SHA256='+$provenance.files.portico),'--env',('PORTICO_UNIT_SHA256='+$provenance.files.'portico-agent.service'),'--volume',((Join-Path $packageRoot 'output')+':/input:ro'),'--volume',((Join-Path $root 'controller')+':/controller-input:ro'),'--volume',($root+':/output:rw'),'--volume',($PSScriptRoot+':/scripts:ro'),'--volume',($driver+':/driver.sh:ro'),$imageLock.image,'bash','/driver.sh')
& docker @dockerArgs 2>&1 | Tee-Object -FilePath (Join-Path $root 'rootfs-build.log')
if ($LASTEXITCODE -ne 0) { throw 'Systemd rootfs creation failed' }
$initramfs = Join-Path $root 'systemd-initramfs.cpio.gz'
$environment = [ordered]@{schema=1;source_revision=$revision;image=$imageLock.image;package_sha256=$qualification.package_sha256;unit_sha256=$provenance.files.'portico-agent.service';binary_sha256=$provenance.files.portico;controller_test_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'controller') -Algorithm SHA256).Hash.ToLowerInvariant();qemu_version=$qemuVersion;qemu_sha256=(Get-FileHash -LiteralPath $qemu -Algorithm SHA256).Hash.ToLowerInvariant();kernel_sha256=$runtimeLock.kernel_sha256.ToLowerInvariant();initramfs_sha256=(Get-FileHash -LiteralPath $initramfs -Algorithm SHA256).Hash.ToLowerInvariant();acceleration='tcg';virtual_cpus=2;memory_mib=3072;network_devices=0;host_filesystem_shares=0}
$environment | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'environment.json') -Encoding utf8
$log = Join-Path $root 'runtime.log'
& timeout --signal=TERM --kill-after=10s 900s $qemu -accel tcg -cpu max -smp 2 -m 3072 -nodefaults -display none -serial stdio -monitor none -nic none -kernel $kernel -initrd $initramfs -append 'console=ttyS0 panic=-1 rdinit=/portico-systemd-init systemd.log_target=console systemd.show_status=yes' -no-reboot *> $log
if ($LASTEXITCODE -ne 0) { throw 'Systemd guest exited unsuccessfully or exceeded its bound' }
$body = Get-Content -Raw -LiteralPath $log
if ($body -notmatch '(?m)^PORTICO_ARCH_SYSTEMD_PASS\r?$' -or $body -notmatch '(?m)^--- PASS: TestSystemdGuestAgentEnrollmentAndRevocation ' -or $body -match 'PORTICO_ARCH_SYSTEMD_FAILED|--- FAIL:|--- SKIP:') { throw 'Actual systemd service qualification failed' }
$result = [ordered]@{schema=1;source_revision=$revision;runtime_log_sha256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant();environment_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'environment.json') -Algorithm SHA256).Hash.ToLowerInvariant();service_execution=$true;user_uid=1000;enrolled_fixture_identity=$true;production_identity=$false;hardware_qualification=$false}
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'qualification.json') -Encoding utf8
Get-Content -LiteralPath $log -Tail 12
