param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
Push-Location $PorticoRoot
try {
    $dirty=@(& git status --porcelain --untracked-files=all)
    if($LASTEXITCODE -ne 0 -or $dirty.Count){throw 'Administrator package preparation requires a clean checkout'}
    $revision=(& git rev-parse HEAD).Trim()
    $epoch=(& git show -s --format=%ct HEAD).Trim()
    if($revision -notmatch '^[0-9a-f]{40}$' -or $epoch -notmatch '^[0-9]+$'){throw 'Missing source provenance'}
    $goVersion=([IO.File]::ReadAllText((Join-Path $PorticoRoot 'tools/toolchain.lock.json'))|ConvertFrom-Json).go.version
    if((& go env GOVERSION) -ne ('go'+$goVersion)){throw 'Wrong pinned Go SDK'}
    $lock=[IO.File]::ReadAllText((Join-Path $PorticoRoot 'desktop/admin/runtime.lock.json'))|ConvertFrom-Json
    $asset=$lock.artifacts.'linux-amd64'
    if($lock.version -notmatch '^\d+\.\d+\.\d+$' -or $asset.file -notmatch '^electron-v[0-9.]+-linux-x64\.zip$' -or $asset.sha256 -notmatch '^[0-9a-f]{64}$'){throw 'Invalid Linux runtime pin'}
    $archive=Join-Path $PorticoWork ('downloads/'+$asset.file)
    if(-not (Test-Path -LiteralPath $archive)){Invoke-WebRequest -Uri ('https://github.com/electron/electron/releases/download/v'+$lock.version+'/'+$asset.file) -OutFile $archive -MaximumRetryCount 2 -RetryIntervalSec 2 -ConnectionTimeoutSeconds 30 -OperationTimeoutSeconds 60}
    if((Get-FileHash -LiteralPath $archive).Hash -ine $asset.sha256){throw 'Pinned runtime digest mismatch'}
    $output=Join-Path $PorticoWork ('admin-package/'+$revision)
    if(Test-Path -LiteralPath $output){throw 'Administrator package output already exists; preserve it'}
    [void][IO.Directory]::CreateDirectory($output)
    $tree=Join-Path $output 'portico-admin-tree.tar.gz'
    & go run ./tools/adminbundle/main.go $tree $archive $asset.sha256 (Join-Path $PorticoRoot 'desktop/admin') $epoch *> (Join-Path $output 'prepare.log')
    if($LASTEXITCODE -ne 0){throw 'Administrator bundle preparation failed'}
    $notice="PORTICO UNSIGNED ADMINISTRATOR DEVELOPMENT PACKAGE`nSource: $revision`nElectron: $($lock.version); pinned upstream archive: $($asset.sha256)`n`nThis is an isolated qualification artifact, not a supported or signed release.`nNo project license grant is made. Preserve Electron LICENSE and LICENSES.chromium.html.`nThe root-owned Chromium sandbox helper is included. No identities, configuration,`nservice activation, network changes, permission repair or recovery are provided.`nRemoving the package leaves user state untouched. Review docs/delivery-status.md.`n"
    [IO.File]::WriteAllText((Join-Path $output 'DEVELOPMENT.txt'),$notice,[Text.UTF8Encoding]::new($false))
    $treeHash=(Get-FileHash -LiteralPath $tree).Hash.ToLowerInvariant()
    $noticeHash=(Get-FileHash -LiteralPath (Join-Path $output 'DEVELOPMENT.txt')).Hash.ToLowerInvariant()
    $version='0.7.0.dev.g'+$revision.Substring(0,12)
    $recipe=[IO.File]::ReadAllText((Join-Path $PorticoRoot 'packaging/arch/PKGBUILD.admin.in')).Replace('@PACKAGE_VERSION@',$version).Replace('@TREE_SHA256@',$treeHash).Replace('@NOTICE_SHA256@',$noticeHash).Replace("`r`n","`n")
    if($recipe -match '@[A-Z_]+@'){throw 'Unresolved administrator package recipe'}
    [IO.File]::WriteAllText((Join-Path $output 'PKGBUILD'),$recipe,[Text.UTF8Encoding]::new($false))
    if($IsLinux){
        # These newly generated, public package inputs must be readable by the
        # separate unprivileged container builder. No identity state is here.
        & chmod 0755 -- $output
        if($LASTEXITCODE -ne 0){throw 'Cannot set public package directory mode'}
        & chmod 0644 -- $tree (Join-Path $output 'PKGBUILD') (Join-Path $output 'DEVELOPMENT.txt')
        if($LASTEXITCODE -ne 0){throw 'Cannot set public package input modes'}
    }
    $record=[ordered]@{schema=1;development_only=$true;source_revision=$revision;source_date_epoch=[long]$epoch;go_version=$goVersion;runtime_version=$lock.version;runtime_archive_sha256=$asset.sha256;tree_sha256=$treeHash;recipe_sha256=(Get-FileHash -LiteralPath (Join-Path $output 'PKGBUILD')).Hash.ToLowerInvariant();package_name='portico-admin-development';package_version=$version}
    [IO.File]::WriteAllText((Join-Path $output 'provenance.json'),($record|ConvertTo-Json -Depth 4)+"`n")
    Write-Output $output
} finally {Pop-Location}
