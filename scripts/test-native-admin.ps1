param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'), [ValidatePattern('^[a-z0-9-]{1,64}$')][string]$RunName = 'native-admin')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$runtime = Get-Content -LiteralPath (Join-Path $PorticoWork 'reports/admin-runtime.json') -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $runtime.executable -Algorithm SHA256).Hash -ine $runtime.executableSHA256) { throw 'Prepared runtime executable changed' }
$env:GOMAXPROCS = '2'
$env:CGO_ENABLED = '1'
$env:PORTICO_NATIVE_EXECUTABLE = $runtime.executable
$env:PORTICO_BROWSER_REPORT = Join-Path $PorticoWork ('reports/' + $RunName + '-browser')
if (Test-Path -LiteralPath $env:PORTICO_BROWSER_REPORT) { throw 'Preserve the prior evidence; choose a fresh RunName' }
Push-Location $PorticoRoot
try {
    & go test -race ./internal/adminbridge -count=1 -v -timeout 2m *> (Join-Path $PorticoWork ('reports/' + $RunName + '-transport.log'))
    if ($LASTEXITCODE -ne 0) { throw 'Native transport tests failed' }
    # The production-cost password KDF is qualified sequentially. This test
    # budget does not change any browser, TLS or administrator session deadline.
    & go test -race ./internal/adminkey -count=1 -v -timeout 8m *> (Join-Path $PorticoWork ('reports/' + $RunName + '-key.log'))
    if ($LASTEXITCODE -ne 0) { throw 'Encrypted administrator key tests failed' }
    & go test -race ./internal/adminapp -count=1 -v -timeout 2m *> (Join-Path $PorticoWork ('reports/' + $RunName + '-app.log'))
    if ($LASTEXITCODE -ne 0) { throw 'Administrator application tests failed' }
    try {
        $env:ELECTRON_RUN_AS_NODE = '1'
        # Electron is a GUI executable on Windows. Own and wait for the process
        # explicitly; PowerShell invocation must not reuse a prior exit status.
        $nodeStart = [Diagnostics.ProcessStartInfo]::new()
        $nodeStart.FileName = $runtime.executable
        $nodeStart.UseShellExecute = $false
        $nodeStart.CreateNoWindow = $true
        $nodeStart.RedirectStandardOutput = $true
        $nodeStart.RedirectStandardError = $true
        $nodeStart.ArgumentList.Add('--test')
        $nodeStart.ArgumentList.Add('--test-reporter=tap')
        $nodeStart.ArgumentList.Add((Join-Path $PorticoRoot 'desktop/admin/channel.test.cjs'))
        $nodeProcess = [Diagnostics.Process]::Start($nodeStart)
        try {
            $stdout = $nodeProcess.StandardOutput.ReadToEndAsync()
            $stderr = $nodeProcess.StandardError.ReadToEndAsync()
            if (-not $nodeProcess.WaitForExit(30000)) { $nodeProcess.Kill($true); $nodeProcess.WaitForExit(); throw 'Native channel test process exceeded deadline' }
            $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
            [IO.File]::WriteAllText((Join-Path $PorticoWork ('reports/' + $RunName + '-channel.log')), $output)
            if ($nodeProcess.ExitCode -ne 0 -or $output -notmatch '# fail 0\b' -or $output -notmatch '# pass [1-9][0-9]*\b') { throw 'Native channel test result was not a verified pass' }
        } finally { $nodeProcess.Dispose() }
    } finally { Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue }
    & go test -race -tags dashboardbrowser ./internal/controller -run '^TestDashboardNativeBrowser(Failure|ClockFault)?$' -count=1 -v -timeout 3m *> (Join-Path $PorticoWork ('reports/' + $RunName + '-browser.log'))
    if ($LASTEXITCODE -ne 0) { throw 'Native browser qualification failed' }
    [ordered]@{ revision=(& git rev-parse HEAD); platform=[Runtime.InteropServices.RuntimeInformation]::OSDescription; go=(& go version); runtime=$runtime; result='PASS'; scope='Native component and virtual-key qualification; no physical keys, platform custody, installed administration package or owner recovery qualification' } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PorticoWork ('reports/' + $RunName + '-summary.json'))
} finally { Pop-Location }
Write-Output 'Native administrator component qualification passed.'
