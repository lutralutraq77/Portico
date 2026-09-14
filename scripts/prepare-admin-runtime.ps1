param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'Native administration qualification currently requires x64' }
$target = if ($IsWindows) { 'windows-amd64' } elseif ($IsLinux) { 'linux-amd64' } else { throw 'Unsupported qualification host' }
$lock = Get-Content -LiteralPath (Join-Path $PorticoRoot 'desktop/admin/runtime.lock.json') -Raw | ConvertFrom-Json
$asset = $lock.artifacts.$target
if ($lock.version -notmatch '^\d+\.\d+\.\d+$' -or $asset.file -notmatch '^electron-v[0-9.]+-(win32|linux)-x64\.zip$' -or $asset.sha256 -notmatch '^[0-9a-f]{64}$') { throw 'Invalid runtime lock' }
$archive = Join-Path $PorticoWork ('downloads/' + $asset.file)
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri ('https://github.com/electron/electron/releases/download/v' + $lock.version + '/' + $asset.file) -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ine $asset.sha256) { throw 'Runtime archive digest mismatch' }
$destination = Join-Path $PorticoWork ('toolchains/admin-electron-' + $lock.version + '-' + $target)
$stamp = Join-Path $destination 'portico-archive.sha256'
if (-not (Test-Path -LiteralPath $destination)) {
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $total = 0L
        if ($zip.Entries.Count -gt 4096) { throw 'Too many runtime entries' }
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -match '(^/|\\|:|(^|/)\.\.?(/|$))') { throw 'Unsafe runtime archive member' }
            $total += $entry.Length
            if ($total -gt 2GB) { throw 'Runtime archive expands beyond limit' }
        }
    } finally { $zip.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $destination)
    [IO.File]::WriteAllText($stamp, $asset.sha256)
}
if (-not (Test-Path -LiteralPath $stamp) -or [IO.File]::ReadAllText($stamp) -cne $asset.sha256) { throw 'Existing runtime has no matching archive provenance' }
$exe = Join-Path $destination $(if ($IsWindows) { 'electron.exe' } else { 'electron' })
if ($IsLinux) {
    & chmod 755 -- $exe (Join-Path $destination 'chrome-sandbox') (Join-Path $destination 'chrome_crashpad_handler')
    if ($LASTEXITCODE -ne 0) { throw 'Runtime executable permissions failed' }
}
if (-not (Test-Path -LiteralPath $exe)) { throw 'Runtime executable missing' }
$record = [ordered]@{ version=$lock.version; target=$target; source=$lock.source; archiveSHA256=$asset.sha256; executableSHA256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant(); executable=$exe }
$record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PorticoWork 'reports/admin-runtime.json')
Write-Output $exe
