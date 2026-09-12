# Reproducible repository-local tool setup. No installer or machine-wide mutation.
param([switch]$SkipToolBuild, [string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$lock = Get-Content -LiteralPath (Join-Path $PorticoRoot 'tools/toolchain.lock.json') -Raw | ConvertFrom-Json
function Get-VerifiedArchive {
    param([string]$Url, [string]$ExpectedSHA256, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Destination)) {
        Invoke-WebRequest -Uri $Url -OutFile $Destination
    }
    $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
    if ($actual -ine $ExpectedSHA256) { throw "Archive checksum mismatch: $Destination" }
}
if ($IsWindows) {
    $goArchive = Join-Path $PorticoWork ('downloads/go' + $lock.go.version + '.windows-amd64.zip')
    Get-VerifiedArchive $lock.go.windows_amd64.url $lock.go.windows_amd64.sha256 $goArchive
    $portableGo = Join-Path $PorticoWork 'toolchains/go/bin/go.exe'
    if (-not (Test-Path -LiteralPath $portableGo)) {
        [IO.Compression.ZipFile]::ExtractToDirectory($goArchive, (Join-Path $PorticoWork 'toolchains'))
    }
    $compilerArchive = Join-Path $PorticoWork ('downloads/w64devkit-x64-' + $lock.windows_compiler.version + '.7z.exe')
    Get-VerifiedArchive $lock.windows_compiler.url $lock.windows_compiler.sha256 $compilerArchive
    if (-not (Test-Path -LiteralPath (Join-Path $PorticoWork 'toolchains/w64devkit/bin/gcc.exe'))) {
        # Server 2022's tar lacks the LZMA codec. The checksum-verified archive
        # includes its own extractor and needs no installer or external codec.
        $extractRoot = Join-Path $PorticoWork 'toolchains'
        $extractor = Start-Process -FilePath $compilerArchive -ArgumentList @('-y', ('-o"' + $extractRoot + '"')) -WindowStyle Hidden -Wait -PassThru
        if ($extractor.ExitCode -ne 0) { throw 'Compiler extraction failed' }
        if (-not (Test-Path -LiteralPath (Join-Path $extractRoot 'w64devkit/bin/gcc.exe'))) {
            throw 'Compiler archive did not produce gcc.exe'
        }
    }
    . (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
}
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64' -or (-not $IsWindows -and -not $IsLinux)) {
    throw 'The pinned generator currently supports Windows and Linux x86_64 hosts.'
}
$protocPlatform='linux_amd64'; $protocSuffix=''
if ($IsWindows) { $protocPlatform='windows_amd64'; $protocSuffix='.exe' }
$protocArchive=Join-Path $PorticoWork ('downloads/protoc-'+$lock.protoc.version+'-'+$protocPlatform+'.zip')
Get-VerifiedArchive $lock.protoc.$protocPlatform.url $lock.protoc.$protocPlatform.sha256 $protocArchive
$protocRoot=Join-Path $PorticoWork ('toolchains/protoc-'+$lock.protoc.version)
$protocBinary=Join-Path $protocRoot ('bin/protoc'+$protocSuffix)
if (-not (Test-Path -LiteralPath $protocBinary)) {
    [IO.Compression.ZipFile]::ExtractToDirectory($protocArchive,$protocRoot)
}
if ($IsLinux) {
    [IO.File]::SetUnixFileMode($protocBinary,[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)
}
if ((& $protocBinary --version) -ne ('libprotoc '+$lock.protoc.version)) { throw 'Pinned protoc version mismatch' }
$actualVersion = & go env GOVERSION
if ($LASTEXITCODE -ne 0 -or $actualVersion -ne ('go' + $lock.go.version)) {
    throw ('Expected Go ' + $lock.go.version + '; use the pinned SDK.')
}
Push-Location (Join-Path $PorticoRoot 'tools')
try {
    & go mod download
    if ($LASTEXITCODE -ne 0) { throw 'Tool dependency download failed' }
    & go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Tool checksum verification failed' }
    if (-not $SkipToolBuild) {
        # Build exactly the tools declared in go.mod; checks scan the same list.
        $packages = @(& go list -f '{{.ImportPath}}' tool)
        if ($LASTEXITCODE -ne 0 -or $packages.Count -eq 0) { throw 'Cannot enumerate development tool packages' }
        foreach ($package in $packages) {
            & go install $package
            if ($LASTEXITCODE -ne 0) { throw "Tool build failed: $package" }
        }
    }
} finally { Pop-Location }
Write-Output ('Pinned development tools ready under ' + $PorticoWork)

