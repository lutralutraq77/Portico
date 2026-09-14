param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$lock = Get-Content -Raw -LiteralPath (Join-Path $PorticoRoot 'tools/arch-ssh.lock.json') | ConvertFrom-Json
if ($lock.schema -ne 1 -or $lock.packages.Count -ne 4) { throw 'Unexpected SSH package lock' }
$root = Join-Path $PorticoWork 'downloads/ssh-arch'
[void][IO.Directory]::CreateDirectory($root)
$checksums = @()
foreach ($package in $lock.packages) {
    if ($package.name -notmatch '^(openssh|libedit)-[a-zA-Z0-9._-]+\.pkg\.tar\.zst(\.sig)?$' -or $package.sha256 -notmatch '^[0-9a-f]{64}$' -or $package.url -ne ('https://archive.archlinux.org/packages/'+$package.name.Substring(0,1)+'/'+($package.name.Split('-')[0])+'/'+$package.name)) { throw 'Invalid SSH package lock entry' }
    $target = Join-Path $root $package.name
    if (-not (Test-Path -LiteralPath $target)) {
        $partial = $target+'.download'
        if (Test-Path -LiteralPath $partial) { throw 'Preserve incomplete package download for inspection' }
        Invoke-WebRequest -Uri $package.url -OutFile $partial -TimeoutSec 60
        if ((Get-FileHash -LiteralPath $partial).Hash -ine $package.sha256) { throw 'SSH package download digest mismatch' }
        Move-Item -LiteralPath $partial -Destination $target
    }
    if ((Get-FileHash -LiteralPath $target).Hash -ine $package.sha256) { throw 'Cached SSH package digest mismatch' }
    $checksums += $package.sha256+'  '+$package.name
}
[IO.File]::WriteAllText((Join-Path $root 'packages.sha256'), ($checksums -join "`n")+"`n", [Text.UTF8Encoding]::new($false))
Write-Output 'Pinned SSH downloads checked; Arch signature verification occurs in the isolated build container.'
