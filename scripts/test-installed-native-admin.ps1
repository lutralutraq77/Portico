param([Parameter(Mandatory=$true)][string]$Prepared, [string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if(-not $IsLinux -or $env:GITHUB_ACTIONS -cne 'true'){throw 'Installed native qualification requires the isolated Linux CI runner'}
$root=[IO.Path]::GetFullPath($Prepared)
$record=[IO.File]::ReadAllText((Join-Path $root 'provenance.json'))|ConvertFrom-Json
if($record.source_revision -ne (& git rev-parse HEAD).Trim() -or $root -cne (Join-Path $PorticoWork ('admin-package/'+$record.source_revision))){throw 'Installed fixture source differs'}
if((& go env GOVERSION) -ne ('go'+$record.go_version)){throw 'Installed fixture toolchain differs'}
$binaryRoot=Join-Path $PorticoWork 'installed-admin'
[void][IO.Directory]::CreateDirectory($binaryRoot)
$binary=Join-Path $binaryRoot 'portico'
$env:GOMAXPROCS='2'
$env:CGO_ENABLED='0'
& go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o $binary ./cmd/portico
if($LASTEXITCODE -ne 0){throw 'Installed CLI build failed'}
& bash (Join-Path $PSScriptRoot 'install-native-admin-fixture.sh') (Join-Path $root 'portico-admin-tree.tar.gz') $binary $record.tree_sha256
if($LASTEXITCODE -ne 0){throw 'Isolated native installation failed'}
$env:CGO_ENABLED='1'
$env:PORTICO_INSTALLED_ADMIN_TEST='1'
try {
    & go test -race -tags dashboardbrowser ./internal/controller -run '^TestInstalledAdministratorCommand$' -count=1 -v -timeout 3m *> (Join-Path $PorticoWork 'reports/native-admin-installed.log')
    if($LASTEXITCODE -ne 0){throw 'Installed administrator command failed'}
} finally {Remove-Item Env:PORTICO_INSTALLED_ADMIN_TEST -ErrorAction SilentlyContinue}
$evidence=[ordered]@{source_revision=$record.source_revision;tree_sha256=$record.tree_sha256;binary_sha256=(Get-FileHash -LiteralPath $binary).Hash.ToLowerInvariant();result='PASS';scope='Unmodified installed CLI, encrypted administrator key, real kernel clock, shipped native entrypoint, authenticated dashboard inventory and cancellation; isolated issuer/model fixtures; no physical hardware or complete bootstrap/recovery'}
[IO.File]::WriteAllText((Join-Path $PorticoWork 'reports/native-admin-installed.json'),($evidence|ConvertTo-Json -Depth 4)+"`n")
Write-Output 'PORTICO_INSTALLED_NATIVE_ADMIN_PASS'
