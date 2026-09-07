param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$fixture=Join-Path $PorticoWork ('tmp/secret-fixture-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$config=Join-Path $fixture 'control.toml'
# Separate default config intentionally has no work/ exclusion for this positive control.
[IO.File]::WriteAllText($config,"[extend]"+[Environment]::NewLine+"useDefault = true",[Text.UTF8Encoding]::new($false))
$canary=Join-Path $fixture 'synthetic.txt'
# Generate a recognizable, synthetic token at runtime. It is not a usable credential.
$synthetic=('gh'+'p_')+([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N').Substring(0,4))
[IO.File]::WriteAllText($canary,('token = "'+$synthetic+'"'),[Text.UTF8Encoding]::new($false))
$report=Join-Path $PorticoWork 'reports/gitleaks-positive-control.json'
& gitleaks dir $fixture --redact --no-banner --config $config --report-format json --report-path $report
$code=$LASTEXITCODE
if($code -ne 1){throw "Secret scanner positive control expected detection exit 1; got $code"}
$findings=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
if(@($findings).Count -lt 1){throw 'Secret scanner returned no findings for positive control'}
Write-Output 'Secret scanner detected and redacted the synthetic positive control.'

