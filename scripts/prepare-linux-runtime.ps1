param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if (-not $IsLinux -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') {
    throw 'Prepare Linux runtime assets on an x64 Linux build host.'
}
foreach ($required in @('tar', 'xorriso', 'ninja', 'cc', 'python3')) {
    if (-not (Get-Command $required -ErrorAction SilentlyContinue)) { throw "Missing build prerequisite: $required" }
}
$lock = Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/linuxvm/assets.lock.json') | ConvertFrom-Json
function Get-VerifiedAsset([string]$Url, [string]$Path, [string]$SHA256) {
    if (-not (Test-Path -LiteralPath $Path)) { Invoke-WebRequest -Uri $Url -OutFile $Path }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $SHA256) {
        throw "Asset checksum mismatch: $Path"
    }
}
$sourceArchive = Join-Path $PorticoWork ('downloads/qemu-' + $lock.linux_qemu.version + '.tar.xz')
Get-VerifiedAsset $lock.linux_qemu.source_url $sourceArchive $lock.linux_qemu.source_sha256
$iso = Join-Path $PorticoWork ('downloads/alpine-virt-' + $lock.alpine_version + '-x86_64.iso')
Get-VerifiedAsset $lock.alpine_url $iso $lock.alpine_sha256
$boot = Join-Path $PorticoWork 'linux/boot'
[IO.Directory]::CreateDirectory($boot) | Out-Null
$kernel = Join-Path $boot 'vmlinuz-virt'
if (-not (Test-Path -LiteralPath $kernel)) {
    & xorriso -osirrox on -indev $iso -extract /boot/vmlinuz-virt $kernel
    if ($LASTEXITCODE -ne 0) { throw 'Cannot extract the pinned guest kernel' }
}
if ((Get-FileHash -LiteralPath $kernel -Algorithm SHA256).Hash -ine $lock.kernel_sha256) {
    throw 'Extracted kernel does not match the pinned artifact'
}
$sourceRoot = Join-Path $PorticoWork 'toolchains/qemu-linux-source'
$source = Join-Path $sourceRoot ('qemu-' + $lock.linux_qemu.version)
$build = Join-Path $PorticoWork ('toolchains/qemu-linux-build-' + $lock.linux_qemu.version)
$prefix = Join-Path $PorticoWork 'toolchains/qemu-linux'
[IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
[IO.Directory]::CreateDirectory($build) | Out-Null
& tar -xf $sourceArchive -C $sourceRoot
if ($LASTEXITCODE -ne 0) { throw 'Cannot extract the verified QEMU source' }
Push-Location $build
try {
    # Bundled source/wheels only: configure may not fetch additional code.
    & (Join-Path $source 'configure') "--prefix=$prefix" --target-list=x86_64-softmmu --without-default-features --enable-tcg --disable-docs --disable-download
    if ($LASTEXITCODE -ne 0) { throw 'QEMU configuration failed' }
    & ninja -j 2
    if ($LASTEXITCODE -ne 0) { throw 'QEMU build failed' }
    & ninja install
    if ($LASTEXITCODE -ne 0) { throw 'QEMU workspace installation failed' }
} finally { Pop-Location }
$qemu = Join-Path $prefix 'bin/qemu-system-x86_64'
$version = (& $qemu --version | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or $version -notmatch ('^QEMU emulator version ' + [regex]::Escape($lock.linux_qemu.version) + '(\s|$)')) {
    throw 'Built QEMU does not report the pinned version'
}
Write-Output $version
