param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
Push-Location $PorticoRoot
$priorOS=$env:GOOS; $priorArch=$env:GOARCH; $priorCGO=$env:CGO_ENABLED
try {
    # Provenance identifies the complete source, including this recipe. Never
    # label a dirty build with the clean commit's identity.
    $dirty = @(& git status --porcelain --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Arch package preparation requires a clean checkout' }
    $revision = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') { throw 'Missing source revision' }
    $epoch = (& git show -s --format=%ct HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $epoch -notmatch '^[0-9]+$') { throw 'Missing source timestamp' }
    $expected = (Get-Content -Raw -LiteralPath tools/toolchain.lock.json | ConvertFrom-Json).go.version
    if ((& go env GOVERSION) -ne ('go' + $expected)) { throw 'Wrong pinned Go SDK' }
    $root = Join-Path $PorticoWork ('arch-package/' + $revision)
    if (Test-Path -LiteralPath $root) { throw 'Package output already exists; preserve its evidence' }
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $utf8 = [Text.UTF8Encoding]::new($false)
    function Write-PackageText([string]$Name, [string]$Text) {
        [IO.File]::WriteAllText((Join-Path $root $Name), $Text.Replace("`r`n", "`n"), $utf8)
    }
    $env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    $binary = Join-Path $root 'portico'
    & go build -trimpath -buildvcs=false '-ldflags=-buildid=' -o $binary ./cmd/portico
    if ($LASTEXITCODE -ne 0) { throw 'Linux application build failed' }
    $buildInfo = (& go version -m -json $binary) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $buildInfo.GoVersion -ne ('go'+$expected) -or $buildInfo.Path -ne 'portico.local/portico/cmd/portico') { throw 'Unexpected application provenance' }
    $settings = @{}
    foreach ($entry in $buildInfo.Settings) { $settings[$entry.Key] = $entry.Value }
    if ($settings['GOOS'] -ne 'linux' -or $settings['GOARCH'] -ne 'amd64' -or $settings['CGO_ENABLED'] -ne '0') { throw 'Unexpected build target' }
    Write-PackageText 'portico.1' ([IO.File]::ReadAllText((Join-Path $PorticoRoot 'packaging/arch/portico.1')))
    $notice = @"
PORTICO — UNSIGNED DEVELOPMENT PACKAGE

Source revision: $revision
Source: https://github.com/lutralutraq77/Portico/tree/$revision
Toolchain: Go $expected; linux/amd64; CGO disabled

This package is for isolated development qualification. It is not a supported
release and makes no license grant. Project licensing, release signers and
distribution trust remain owner decisions. Do not publish it as a release.

Installation provides the command and its manual only. Approved configuration,
independently verified trust and provisioned private services remain necessary.
There is no automatic enrollment, service activation, port publication, password
store, network change or permission repair. Removing the package leaves user
identity/configuration files untouched because those files are not in the package.

See the source revision's docs/delivery-status.md for open platform, hardware,
network, update and acceptance gates. Ordinary host/container package tests do
not replace the isolated Linux security suite or real hardware qualification.
"@
    Write-PackageText 'DEVELOPMENT.txt' ($notice + "`n")
    $hashes = @{}
    foreach ($name in @('portico','portico.1','DEVELOPMENT.txt')) {
        $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $packageVersion = '0.6.0.dev.g' + $revision.Substring(0,12)
    $recipe = [IO.File]::ReadAllText((Join-Path $PorticoRoot 'packaging/arch/PKGBUILD.in'))
    $recipe = $recipe.Replace('@PACKAGE_VERSION@',$packageVersion).Replace('@BINARY_SHA256@',$hashes['portico']).Replace('@MANUAL_SHA256@',$hashes['portico.1']).Replace('@NOTICE_SHA256@',$hashes['DEVELOPMENT.txt'])
    if ($recipe -match '@[A-Z_]+@') { throw 'Unresolved package recipe field' }
    Write-PackageText 'PKGBUILD' $recipe
    $hashes['PKGBUILD'] = (Get-FileHash -LiteralPath (Join-Path $root 'PKGBUILD') -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-PackageText 'provenance.json' (([ordered]@{schema=1;development_only=$true;source_revision=$revision;source_date_epoch=[long]$epoch;go_version=$expected;target='linux/amd64';package_name='portico-cli-development';package_version=$packageVersion;files=$hashes} | ConvertTo-Json -Depth 4) + "`n")
    Write-PackageText 'buildinfo.json' (($buildInfo | ConvertTo-Json -Depth 12) + "`n")
    Write-Output $root
} finally {
    $env:GOOS=$priorOS; $env:GOARCH=$priorArch; $env:CGO_ENABLED=$priorCGO
    Pop-Location
}
