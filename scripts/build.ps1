param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$buildRoot = Join-Path $PorticoRoot 'build'
[IO.Directory]::CreateDirectory($buildRoot) | Out-Null
$priorOS=$env:GOOS; $priorArch=$env:GOARCH; $priorCGO=$env:CGO_ENABLED
Push-Location $PorticoRoot
try {
    $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    foreach($target in @('windows','linux')) {
        $env:GOOS=$target
        $suffix=''; if($target -eq 'windows'){$suffix='.exe'}
        $output=Join-Path $buildRoot ('portico-'+$target+'-amd64'+$suffix)
        & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o $output ./cmd/portico
        if($LASTEXITCODE -ne 0){throw "Build failed: $target"}
    }
    $env:GOOS=$priorOS; $env:GOARCH=$priorArch
    $native=Join-Path $buildRoot 'portico-linux-amd64'
    if($IsWindows){$native=Join-Path $buildRoot 'portico-windows-amd64.exe'}
    & $native version --json
    if($LASTEXITCODE -ne 0){throw 'Native binary smoke test failed'}
    $first=(Get-FileHash -LiteralPath $native -Algorithm SHA256).Hash
    $second=Join-Path $PorticoWork 'reports/rebuild'
    if($IsWindows){$second+='.exe'}
    & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o $second ./cmd/portico
    if($LASTEXITCODE -ne 0){throw 'Rebuild failed'}
    if((Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash -ne $first){throw 'Same-toolchain native rebuild was not byte-identical'}
    Get-FileHash -LiteralPath (Join-Path $buildRoot 'portico-windows-amd64.exe'),(Join-Path $buildRoot 'portico-linux-amd64') -Algorithm SHA256 |
        Select-Object Path,Hash | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PorticoWork 'reports/build-hashes.json')
} finally {
    $env:GOOS=$priorOS; $env:GOARCH=$priorArch; $env:CGO_ENABLED=$priorCGO
    Pop-Location
}

