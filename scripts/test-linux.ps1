param([switch]$WorkloadOnly, [switch]$AdministratorOnly, [ValidatePattern('^[a-z0-9-]{1,64}$')][string]$RunName = 'linux-admin-key-runtime', [string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
if ($WorkloadOnly -and $AdministratorOnly) { throw 'Select one focused guest suite.' }
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if (-not $IsWindows -and -not $IsLinux) { throw 'The isolated guest harness supports Windows and Linux hosts.' }
$qemu=Join-Path $PorticoWork 'toolchains/qemu/qemu-system-x86_64.exe'
if ($IsLinux) { $qemu=Join-Path $PorticoWork 'toolchains/qemu-linux/bin/qemu-system-x86_64' }
$kernel=Join-Path $PorticoWork 'linux/boot/vmlinuz-virt'
if (-not (Test-Path -LiteralPath $qemu) -or -not (Test-Path -LiteralPath $kernel)) {throw 'Prepare the pinned QEMU/kernel assets described in docs/linux-runtime.md'}
$lock=Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/linuxvm/assets.lock.json')|ConvertFrom-Json
$expectedQemu=$lock.qemu_version
if ($IsLinux) { $expectedQemu=$lock.linux_qemu.version }
$qemuVersion=(& $qemu --version | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or $qemuVersion -notmatch ('^QEMU emulator version '+[regex]::Escape($expectedQemu)+'(\s|$)')) {throw 'QEMU version differs from the pinned toolchain'}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $kernel).Hash -ine $lock.kernel_sha256){throw 'Linux kernel checksum differs from pinned artifact'}
$vm=Join-Path $PorticoWork 'linux'
$initPath=Join-Path $vm 'init'
$archivePath=Join-Path $vm 'tests.cpio.gz'
if ($AdministratorOnly) {
 $initPath=Join-Path $vm 'admin-key-init'
 $archivePath=Join-Path $vm 'admin-key-tests.cpio.gz'
 if (Test-Path -LiteralPath (Join-Path $PorticoWork ('reports/'+$RunName+'.log'))) { throw 'Preserve the prior administrator guest report; choose a fresh RunName.' }
}
$priorOS=$env:GOOS;$priorArch=$env:GOARCH;$priorCGO=$env:CGO_ENABLED
Push-Location $PorticoRoot
try {
 $env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
 & go build -trimpath -buildvcs=false -o $initPath ./tools/linuxvm/init/main_linux.go
 if ($LASTEXITCODE -ne 0){throw 'Linux test init build failed'}
 $packages=@('cli','controller','pki','adminauth','wire','carrier','control','boottime','workload','clockhealth','connector','localfile','client','enrollment','localipc','agent','adminkey','adminapp')
 if ($AdministratorOnly) { $packages=@('adminkey','adminapp') }
 foreach($package in $packages){
  & go test -c -o (Join-Path $vm $package) ('./internal/'+$package)
  if ($LASTEXITCODE -ne 0){throw ('Linux test build failed: '+$package)}
 }
 if (-not $AdministratorOnly) {
 & go test -c -o (Join-Path $vm 'adapter') ./internal/issuer
 if ($LASTEXITCODE -ne 0){throw 'Linux issuer adapter test build failed'}
 Push-Location (Join-Path $PorticoRoot 'issuer')
 try {
  & go test -c -o (Join-Path $vm 'issuer') .
  if ($LASTEXITCODE -ne 0){throw 'Linux issuer test build failed'}
 } finally {Pop-Location}
 & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o (Join-Path $vm 'portico') ./cmd/portico
 if ($LASTEXITCODE -ne 0){throw 'Linux application build failed'}
 }
 $env:GOOS=$priorOS;$env:GOARCH=$priorArch;$env:CGO_ENABLED=$priorCGO
 if ($AdministratorOnly) {
  & go run ./tools/linuxvm/archive/main.go $archivePath $initPath (Join-Path $vm 'adminkey') (Join-Path $vm 'adminapp')
 } else {
  & go run ./tools/linuxvm/archive/main.go $archivePath $initPath (Join-Path $vm 'cli') (Join-Path $vm 'controller') (Join-Path $vm 'pki') (Join-Path $vm 'adminauth') (Join-Path $vm 'wire') (Join-Path $vm 'carrier') (Join-Path $vm 'control') (Join-Path $vm 'boottime') (Join-Path $vm 'workload') (Join-Path $vm 'clockhealth') (Join-Path $vm 'connector') (Join-Path $vm 'localfile') (Join-Path $vm 'client') (Join-Path $vm 'enrollment') (Join-Path $vm 'adapter') (Join-Path $vm 'issuer') (Join-Path $vm 'portico') (Join-Path $vm 'localipc') (Join-Path $vm 'agent') (Join-Path $vm 'adminkey') (Join-Path $vm 'adminapp')
 }
 if ($LASTEXITCODE -ne 0){throw 'Test initramfs creation failed'}
 $log=Join-Path $PorticoWork 'reports/linux-runtime.log'
 $arguments='console=ttyS0 panic=-1 rdinit=/init'
 $passMarker='PORTICO_LINUX_ALL_PASS'
 if ($WorkloadOnly) {
  $log=Join-Path $PorticoWork 'reports/linux-workload-runtime.log'
  $arguments+=' portico.workload-only=1'
  $passMarker='PORTICO_LINUX_WORKLOAD_PASS'
 }
 if ($AdministratorOnly) {
  $log=Join-Path $PorticoWork ('reports/'+$RunName+'.log')
  $arguments+=' portico.administrator-only=1'
  $passMarker='PORTICO_LINUX_ADMINISTRATOR_PASS'
 }
 $environment=[ordered]@{
  host=[Runtime.InteropServices.RuntimeInformation]::OSDescription
  qemu_version=$qemuVersion
  qemu_sha256=(Get-FileHash -LiteralPath $qemu -Algorithm SHA256).Hash.ToLowerInvariant()
  kernel_sha256=$lock.kernel_sha256.ToLowerInvariant()
  initramfs_sha256=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
  acceleration='tcg'; virtual_cpus=2; memory_mib=1536; network_devices=0; host_filesystem_shares=0
  workload_only=[bool]$WorkloadOnly
  administrator_only=[bool]$AdministratorOnly
 }
 $environmentPath=Join-Path $PorticoWork 'reports/linux-runtime-environment.json'
 if ($AdministratorOnly) { $environmentPath=Join-Path $PorticoWork ('reports/'+$RunName+'-environment.json') }
 $environment | ConvertTo-Json | Set-Content -LiteralPath $environmentPath -Encoding utf8
 & $qemu -accel tcg -cpu max -smp 2 -m 1536 -nodefaults -display none -serial stdio -monitor none -nic none -kernel $kernel -initrd $archivePath -append $arguments -no-reboot *> $log
 if ($LASTEXITCODE -ne 0){throw 'QEMU exited unsuccessfully'}
 $body=Get-Content -Raw -LiteralPath $log
 if ($body -notmatch ('(?m)^'+$passMarker+'\r?$') -or $body -match 'PORTICO_FAIL|--- FAIL:'){throw ('Linux runtime tests failed; see '+$log)}
 Get-Content -LiteralPath $log -Tail 12
} finally {
 $env:GOOS=$priorOS;$env:GOARCH=$priorArch;$env:CGO_ENABLED=$priorCGO
 Pop-Location
}
