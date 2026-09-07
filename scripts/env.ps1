# Dot-source this file to configure this process only; no global settings.
param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
$script:PorticoRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$script:PorticoWork = [IO.Path]::GetFullPath($WorkRoot)
if ($IsWindows -and [IO.Path]::GetPathRoot($script:PorticoWork) -eq 'C:\') {
    throw 'Development storage must be off C:. Pass an E: WorkRoot.'
}
foreach ($name in @('tmp','gopath','gomodcache','gocache','bin','reports','downloads','toolchains','xdg-cache','xdg-config')) {
    [IO.Directory]::CreateDirectory((Join-Path $script:PorticoWork $name)) | Out-Null
}
$env:TEMP = Join-Path $script:PorticoWork 'tmp'
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:GOTMPDIR = $env:TEMP
$env:GOPATH = Join-Path $script:PorticoWork 'gopath'
$env:GOMODCACHE = Join-Path $script:PorticoWork 'gomodcache'
$env:GOCACHE = Join-Path $script:PorticoWork 'gocache'
$env:GOBIN = Join-Path $script:PorticoWork 'bin'
$env:XDG_CACHE_HOME = Join-Path $script:PorticoWork 'xdg-cache'
$env:XDG_CONFIG_HOME = Join-Path $script:PorticoWork 'xdg-config'
$env:GOTOOLCHAIN = 'local'

$env:GOENV = 'off'
$env:GOPROXY = 'https://proxy.golang.org'
$env:GOSUMDB = 'sum.golang.org'
$env:GOFLAGS = '-mod=readonly'
$goBin = Join-Path $script:PorticoWork 'toolchains/go/bin'
$gccBin = Join-Path $script:PorticoWork 'toolchains/w64devkit/bin'
foreach ($directory in @($env:GOBIN, $gccBin, $goBin)) {
    if (Test-Path -LiteralPath $directory) {
        $env:PATH = $directory + [IO.Path]::PathSeparator + $env:PATH
    }
}
if ($IsWindows -and (Test-Path -LiteralPath (Join-Path $gccBin 'gcc.exe'))) {
    # Go parses CC as a command line, so preserve spaces in the executable path.
    $env:CC = '"' + (Join-Path $gccBin 'gcc.exe') + '"'
}


# A nested module prevents ./... from treating caches and upstream research as application source.
$scratchModule = Join-Path $script:PorticoWork 'go.mod'
if (-not (Test-Path -LiteralPath $scratchModule)) {
    [IO.File]::WriteAllText($scratchModule,"module portico.local/scratch"+[Environment]::NewLine+[Environment]::NewLine+"go 1.27.1"+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
}

# Go telemetry is controlled by a config file, not the GOTELEMETRY environment variable.
# Keep OS-resolved user configuration local to the task, then disable it there.
if ($IsWindows) {
    $env:APPDATA = Join-Path $script:PorticoWork 'appdata'
    $env:LOCALAPPDATA = Join-Path $script:PorticoWork 'localappdata'
    [IO.Directory]::CreateDirectory($env:APPDATA) | Out-Null
    [IO.Directory]::CreateDirectory($env:LOCALAPPDATA) | Out-Null
}
if (Get-Command go -ErrorAction SilentlyContinue) {
    & go telemetry off
    if ($LASTEXITCODE -ne 0) { throw 'Cannot disable Go telemetry in the task configuration directory' }
}
