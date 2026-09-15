param([Parameter(Mandatory=$true)][string]$Prepared, [string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if(-not $IsLinux){throw 'Administrator package qualification requires a Linux Docker host'}
$root=[IO.Path]::GetFullPath($Prepared)
$record=[IO.File]::ReadAllText((Join-Path $root 'provenance.json'))|ConvertFrom-Json
if($record.source_revision -notmatch '^[0-9a-f]{40}$' -or $root -cne (Join-Path $PorticoWork ('admin-package/'+$record.source_revision))){throw 'Unexpected administrator package input'}
if((Get-FileHash -LiteralPath (Join-Path $root 'portico-admin-tree.tar.gz')).Hash -ine $record.tree_sha256 -or (Get-FileHash -LiteralPath (Join-Path $root 'PKGBUILD')).Hash -ine $record.recipe_sha256){throw 'Prepared administrator package changed'}
$lock=[IO.File]::ReadAllText((Join-Path $PorticoRoot 'tools/arch-package.lock.json'))|ConvertFrom-Json
if($lock.image -notmatch '^quay\.io/archlinux/archlinux@sha256:[0-9a-f]{64}$' -or $lock.platform -ne 'linux/amd64'){throw 'Invalid Arch image pin'}
$output=Join-Path $root 'output'
if(Test-Path -LiteralPath $output){throw 'Preserve existing administrator package output'}
[void][IO.Directory]::CreateDirectory($output)
& chmod 0777 -- $output
if($LASTEXITCODE -ne 0){throw 'Cannot prepare public package output'}
& docker pull --platform $lock.platform $lock.image
if($LASTEXITCODE -ne 0){throw 'Cannot fetch pinned Arch image'}
$driver=Join-Path $PSScriptRoot 'arch-admin-build-fixture.sh'
& docker run --rm --pull=never --platform $lock.platform --network=none --read-only --user=nobody --cap-drop=ALL --security-opt=no-new-privileges --tmpfs '/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777' --env LC_ALL=C --env ('SOURCE_DATE_EPOCH='+$record.source_date_epoch) --volume ($root+':/input:ro') --volume ($output+':/output:rw') --volume ($driver+':/driver.sh:ro') $lock.image bash /driver.sh *> (Join-Path $root 'arch-build.log')
if($LASTEXITCODE -ne 0){Get-Content -LiteralPath (Join-Path $root 'arch-build.log') -Tail 100; throw 'Arch administrator package build failed'}
$driver=Join-Path $PSScriptRoot 'arch-admin-install-fixture.sh'
& docker run --rm --pull=never --platform $lock.platform --network=none --security-opt=no-new-privileges --env LC_ALL=C --volume ($output+':/input:ro') --volume ($driver+':/driver.sh:ro') $lock.image bash /driver.sh *> (Join-Path $root 'arch-install.log')
if($LASTEXITCODE -ne 0){Get-Content -LiteralPath (Join-Path $root 'arch-install.log') -Tail 100; throw 'Arch administrator package install/remove failed'}
$packages=@(Get-ChildItem -LiteralPath $output -Filter '*.pkg.tar.zst' -File)
if($packages.Count -ne 1){throw 'Unexpected administrator package result'}
$evidence=[ordered]@{source_revision=$record.source_revision;tree_sha256=$record.tree_sha256;image=$lock.image;package=$packages[0].Name;package_sha256=(Get-FileHash -LiteralPath $packages[0].FullName).Hash.ToLowerInvariant();build='PASS';install_remove='PASS';network='none';runtime_execution=$false;limitations='Offline packaging fixture omits dependency installation; actual native runtime is tested separately on Ubuntu'}
[IO.File]::WriteAllText((Join-Path $root 'arch-qualification.json'),($evidence|ConvertTo-Json -Depth 4)+"`n")
Write-Output 'PORTICO_ARCH_ADMIN_PACKAGE_PASS'
