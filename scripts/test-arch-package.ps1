param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if (-not $IsLinux) { throw 'Arch container qualification requires a Linux Docker host' }
$lock = Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/arch-package.lock.json') | ConvertFrom-Json
if ($lock.image -notmatch '^quay\.io/archlinux/archlinux@sha256:[0-9a-f]{64}$' -or $lock.platform -ne 'linux/amd64') { throw 'Invalid Arch image pin' }
$prepared = @(& (Join-Path $PSScriptRoot 'prepare-arch-package.ps1') -WorkRoot $PorticoWork)
if ($prepared.Count -ne 1) { throw 'Unexpected package preparation output' }
$root = [string]$prepared[0]
$provenance = Get-Content -Raw -LiteralPath (Join-Path $root 'provenance.json') | ConvertFrom-Json
$output = Join-Path $root 'output'
[IO.Directory]::CreateDirectory($output) | Out-Null
# Only public development artifacts are writable to the unprivileged builder.
# Runtime configuration and identity files are never mounted into this fixture.
& chmod 0777 $output
if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare public artifact output' }
& docker pull --platform $lock.platform $lock.image
if ($LASTEXITCODE -ne 0) { throw 'Cannot fetch pinned Arch build image' }
$imageInfo = & docker image inspect $lock.image
if ($LASTEXITCODE -ne 0) { throw 'Cannot record Arch image identity' }
[IO.File]::WriteAllText((Join-Path $root 'image.json'), ($imageInfo -join "`n"))
$driver = Join-Path $PSScriptRoot 'arch-build-fixture.sh'
$dockerArgs = @('run','--rm','--pull=never','--platform',$lock.platform,'--network=none','--read-only','--user=nobody','--cap-drop=ALL','--security-opt=no-new-privileges','--tmpfs','/tmp:rw,nosuid,nodev,size=512m,mode=1777','--env','LC_ALL=C','--env',('SOURCE_DATE_EPOCH='+$provenance.source_date_epoch),'--volume',($root+':/input:ro'),'--volume',($output+':/output:rw'),'--volume',($driver+':/driver.sh:ro'),$lock.image,'bash','/driver.sh')
& docker @dockerArgs 2>&1 | Tee-Object -FilePath (Join-Path $root 'build.log')
if ($LASTEXITCODE -ne 0) { throw 'Arch package build fixture failed' }
$driver = Join-Path $PSScriptRoot 'arch-install-fixture.sh'
$dockerArgs = @('run','--rm','--pull=never','--platform',$lock.platform,'--network=none','--security-opt=no-new-privileges','--env','LC_ALL=C','--env',('PORTICO_BINARY_SHA256='+$provenance.files.portico),'--volume',($output+':/input:ro'),'--volume',($driver+':/driver.sh:ro'),$lock.image,'bash','/driver.sh')
& docker @dockerArgs 2>&1 | Tee-Object -FilePath (Join-Path $root 'install.log')
if ($LASTEXITCODE -ne 0) { throw 'Arch install/remove fixture failed' }
$artifacts = @(Get-ChildItem -LiteralPath $output -Filter '*.pkg.tar.zst' -File)
if ($artifacts.Count -ne 1) { throw 'Unexpected Arch package artifacts' }
$evidence = [ordered]@{schema=1;development_only=$true;source_revision=$provenance.source_revision;image=$lock.image;platform=$lock.platform;package=$artifacts[0].Name;package_sha256=(Get-FileHash -LiteralPath $artifacts[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant();build_log_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'build.log') -Algorithm SHA256).Hash.ToLowerInvariant();install_log_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'install.log') -Algorithm SHA256).Hash.ToLowerInvariant();network='none during package build and installation';service_execution=$false;hardware_qualification=$false}
[IO.File]::WriteAllText((Join-Path $root 'qualification.json'), ($evidence | ConvertTo-Json -Depth 4))
Write-Output 'PORTICO_ARCH_PACKAGE_PASS'
