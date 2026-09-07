param([switch]$SkipScanners, [switch]$SkipRace, [string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$reportRoot = Join-Path $PorticoWork 'reports'
function Invoke-Check {
    param([string]$Name, [string]$Program, [string[]]$Arguments)
    Write-Output "Checking $Name"
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit $LASTEXITCODE)" }
}
Push-Location $PorticoRoot
try {
    $expected = (Get-Content -LiteralPath 'tools/toolchain.lock.json' -Raw | ConvertFrom-Json).go.version
    if ((& go env GOVERSION) -ne ('go' + $expected)) { throw 'Wrong Go SDK version' }

    $environment = (& go env -json GOCACHE GOMODCACHE GOPATH GOTMPDIR GOTELEMETRY GOTELEMETRYDIR) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $environment.GOTELEMETRY -ne 'off') { throw 'Go telemetry is not disabled' }
    $workPrefix = $PorticoWork.TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($name in @('GOCACHE','GOMODCACHE','GOPATH','GOTMPDIR','GOTELEMETRYDIR')) {
        $value = [IO.Path]::GetFullPath($environment.$name)
        if (-not $value.StartsWith($workPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw ('Go storage escaped the task work directory: ' + $name)
        }
    }

    & (Join-Path $PSScriptRoot 'check-docs.ps1') -Root $PorticoRoot -Report (Join-Path $reportRoot 'documentation.json')
    & (Join-Path $PSScriptRoot 'test-check-docs.ps1') -WorkRoot $PorticoWork

    $workflowFiles = @(Get-ChildItem -LiteralPath '.github/workflows' -Filter '*.yml' -File)
    foreach ($workflow in $workflowFiles) {
        $yaml = [IO.File]::ReadAllText($workflow.FullName)
        foreach ($reference in [regex]::Matches($yaml,'(?m)^\s*-\s*uses:\s*([^#\r\n]+)')) {
            $value = $reference.Groups[1].Value.Trim()
            if (-not $value.StartsWith('./') -and $value -notmatch '@[0-9a-f]{40}$') {
                throw ('Unpinned external action: ' + $workflow.Name)
            }
        }
        if ($yaml -match 'pull_request_target|permissions:\s*write-all|secrets\.') {
            throw ('Workflow exceeds the development credential/permission scope: ' + $workflow.Name)
        }
    }

    $sources = @(& git ls-files --cached --others --exclude-standard -- '*.go')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate repository source' }
    $unformatted = @(& gofmt -l @sources)
    if ($LASTEXITCODE -ne 0 -or $unformatted.Count -gt 0) { throw ('Unformatted Go files: ' + ($unformatted -join ', ')) }
    Invoke-Check 'module verification' 'go' @('mod','verify')
    Invoke-Check 'vet' 'go' @('vet','./...')
    Invoke-Check 'shuffled unit tests and coverage' 'go' @('test','-count=1','-shuffle=on',('-coverprofile=' + (Join-Path $reportRoot 'coverage.out')),'./...')
    if (-not $SkipRace) {
        $priorCGO = $env:CGO_ENABLED
        try { $env:CGO_ENABLED = '1'; Invoke-Check 'race detector' 'go' @('test','-race','-count=1','./...') }
        finally { $env:CGO_ENABLED = $priorCGO }
    }
    Invoke-Check 'bounded CLI fuzzing' 'go' @('test','./internal/cli','-run=^$','-fuzz=FuzzCommandSurface','-fuzztime=5s','-parallel=2')
    Invoke-Check 'bounded destination fuzzing' 'go' @('test','./internal/controller','-run=^$','-fuzz=FuzzDestination','-fuzztime=5s','-parallel=2')
    Invoke-Check 'bounded PKI fuzzing' 'go' @('test','./internal/pki','-run=^$','-fuzz=FuzzPKIInputs','-fuzztime=5s','-parallel=2')
    Invoke-Check 'bounded WebAuthn fuzzing' 'go' @('test','./internal/adminauth','-run=^$','-fuzz=FuzzWebAuthnResponses','-fuzztime=5s','-parallel=2')
    Push-Location (Join-Path $PorticoRoot 'issuer')
    try {
        Invoke-Check 'issuer module verification' 'go' @('mod','verify')
        Invoke-Check 'issuer vet' 'go' @('vet','./...')
        Invoke-Check 'real issuer runtime tests' 'go' @('test','-count=1','-shuffle=on',('-coverprofile=' + (Join-Path $reportRoot 'issuer-coverage.out')),'./...')
        if (-not $SkipRace) {
            $priorCGO = $env:CGO_ENABLED
            try { $env:CGO_ENABLED='1'; Invoke-Check 'issuer race detector' 'go' @('test','-race','-count=1','./...') }
            finally { $env:CGO_ENABLED=$priorCGO }
        }
        if (-not $SkipScanners) {
            Invoke-Check 'issuer static analysis' 'staticcheck' @('./...')
            Invoke-Check 'issuer package vulnerabilities' 'govulncheck' @('-scan=package','./...')
        }
    } finally { Pop-Location }
    & (Join-Path $PSScriptRoot 'build.ps1') -WorkRoot $PorticoWork
    if (-not $SkipScanners) {
        # Binary mode records linked dependencies and binary hashes. Module mode
        # recursively hashes the local parent replacement, including work caches.
        foreach ($target in @('windows','linux')) {
            $suffix=''; if ($target -eq 'windows') { $suffix='.exe' }
            $binary=Join-Path $PorticoRoot ('build/portico-issuer-'+$target+'-amd64'+$suffix)
            $bomPath=Join-Path $reportRoot ('issuer-'+$target+'-sbom.cdx.json')
            Invoke-Check ('issuer '+$target+' binary SBOM') 'cyclonedx-gomod' @('bin','-std','-json','-output',$bomPath,$binary)
            $bom=Get-Content -LiteralPath $bomPath -Raw | ConvertFrom-Json
            foreach ($required in @('portico.local/portico','github.com/smallstep/certificates','std')) {
                if ($required -notin $bom.components.name) { throw ('Issuer SBOM missing component: '+$required) }
            }
            $recordedHash=@($bom.metadata.properties | Where-Object name -eq 'cdx:gomod:binary:hash:SHA-256')
            if ($recordedHash.Count -ne 1 -or $recordedHash[0].value -ine (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash) {
                throw 'Issuer SBOM does not identify the built binary'
            }
        }
        Invoke-Check 'static analysis' 'staticcheck' @('./...')
        Invoke-Check 'application vulnerabilities' 'govulncheck' @('./...')

        Push-Location (Join-Path $PorticoRoot 'tools')
        try {
            # A tool-only module has no root packages; module-only scanning can
            # therefore report success without inspecting the tool imports.
            $toolPackages = @(& go list -f '{{.ImportPath}}' tool)
            if ($LASTEXITCODE -ne 0 -or $toolPackages.Count -eq 0) { throw 'Cannot enumerate development tool packages' }
            Invoke-Check 'development tool package vulnerabilities' 'govulncheck' (@('-scan=package') + $toolPackages)
        }
        finally { Pop-Location }
        & (Join-Path $PSScriptRoot 'test-vulnerability-scanner.ps1') -WorkRoot $PorticoWork

        Invoke-Check 'workflow syntax' 'actionlint' @('-shellcheck=','-pyflakes=')
        Invoke-Check 'source secrets' 'gitleaks' @('dir','.', '--redact','--no-banner','--config=.gitleaks.toml','--report-format=json',('--report-path=' + (Join-Path $reportRoot 'gitleaks.json')))
        & (Join-Path $PSScriptRoot 'test-secret-scanner.ps1') -WorkRoot $PorticoWork
        Invoke-Check 'application SBOM' 'cyclonedx-gomod' @('mod','-std','-json','-output',(Join-Path $reportRoot 'sbom.cdx.json'))
    }
} finally { Pop-Location }
Write-Output 'Selected checks passed. See the acceptance manifest for implemented versus planned runtime cases.'

