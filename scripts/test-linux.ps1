param([switch]$WorkloadOnly, [string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if (-not $IsWindows) { throw 'This harness uses portable Windows QEMU; Linux hosts should run check.ps1 natively.' }
$qemu=Join-Path $PorticoWork 'toolchains/qemu/qemu-system-x86_64.exe'
$kernel=Join-Path $PorticoWork 'linux/boot/vmlinuz-virt'
if (-not (Test-Path -LiteralPath $qemu) -or -not (Test-Path -LiteralPath $kernel)) {throw 'Prepare the pinned QEMU/kernel assets described in docs/linux-runtime.md'}
$lock=Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/linuxvm/assets.lock.json')|ConvertFrom-Json
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $kernel).Hash -ine $lock.kernel_sha256){throw 'Linux kernel checksum differs from pinned artifact'}
$vm=Join-Path $PorticoWork 'linux'
$priorOS=$env:GOOS;$priorArch=$env:GOARCH;$priorCGO=$env:CGO_ENABLED
Push-Location $PorticoRoot
try {
 $env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
 & go build -trimpath -buildvcs=false -o (Join-Path $vm 'init') ./tools/linuxvm/init/main_linux.go
 if ($LASTEXITCODE -ne 0){throw 'Linux test init build failed'}
 foreach($package in @('cli','controller','pki','adminauth','wire','carrier','control','boottime','workload','clockhealth','connector')){
  & go test -c -o (Join-Path $vm $package) ('./internal/'+$package)
  if ($LASTEXITCODE -ne 0){throw ('Linux test build failed: '+$package)}
 }
 & go test -c -o (Join-Path $vm 'adapter') ./internal/issuer
 if ($LASTEXITCODE -ne 0){throw 'Linux issuer adapter test build failed'}
 Push-Location (Join-Path $PorticoRoot 'issuer')
 try {
  & go test -c -o (Join-Path $vm 'issuer') .
  if ($LASTEXITCODE -ne 0){throw 'Linux issuer test build failed'}
 } finally {Pop-Location}
 & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o (Join-Path $vm 'portico') ./cmd/portico
 if ($LASTEXITCODE -ne 0){throw 'Linux application build failed'}
 $env:GOOS=$priorOS;$env:GOARCH=$priorArch;$env:CGO_ENABLED=$priorCGO
 & go run ./tools/linuxvm/archive/main.go (Join-Path $vm 'tests.cpio.gz') (Join-Path $vm 'init') (Join-Path $vm 'cli') (Join-Path $vm 'controller') (Join-Path $vm 'pki') (Join-Path $vm 'adminauth') (Join-Path $vm 'wire') (Join-Path $vm 'carrier') (Join-Path $vm 'control') (Join-Path $vm 'boottime') (Join-Path $vm 'workload') (Join-Path $vm 'clockhealth') (Join-Path $vm 'connector') (Join-Path $vm 'adapter') (Join-Path $vm 'issuer') (Join-Path $vm 'portico')
 if ($LASTEXITCODE -ne 0){throw 'Test initramfs creation failed'}
 $log=Join-Path $PorticoWork 'reports/linux-runtime.log'
 $arguments='console=ttyS0 panic=-1 rdinit=/init'
 $passMarker='PORTICO_LINUX_ALL_PASS'
 if ($WorkloadOnly) {
  $log=Join-Path $PorticoWork 'reports/linux-workload-runtime.log'
  $arguments+=' portico.workload-only=1'
  $passMarker='PORTICO_LINUX_WORKLOAD_PASS'
 }
 & $qemu -accel tcg -cpu max -smp 2 -m 1536 -nodefaults -display none -serial stdio -monitor none -nic none -kernel $kernel -initrd (Join-Path $vm 'tests.cpio.gz') -append $arguments -no-reboot *> $log
 if ($LASTEXITCODE -ne 0){throw 'QEMU exited unsuccessfully'}
 $body=Get-Content -Raw -LiteralPath $log
 if ($body -notmatch ('(?m)^'+$passMarker+'\r?$') -or $body -match 'PORTICO_FAIL|--- FAIL:'){throw ('Linux runtime tests failed; see '+$log)}
 Get-Content -LiteralPath $log -Tail 12
} finally {
 $env:GOOS=$priorOS;$env:GOARCH=$priorArch;$env:CGO_ENABLED=$priorCGO
 Pop-Location
}
