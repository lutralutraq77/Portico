param([string]$WorkRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$fixtureRoot=Join-Path $PorticoWork ('tmp/docs-fixtures-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$checker=Join-Path $PSScriptRoot 'check-docs.ps1'
$files=@(& git -C $PorticoRoot ls-files --cached --others --exclude-standard)
if($LASTEXITCODE -ne 0){throw 'Fixture enumeration failed'}
foreach($relative in $files){
    # Copies only repository source, never cache, secrets or production state.
    $destination=Join-Path $fixtureRoot $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
    [IO.File]::Copy((Join-Path $PorticoRoot $relative),$destination,$true)
}
& $checker -Root $fixtureRoot -Quiet
$probe=Join-Path $fixtureRoot 'README.md'
$baseline=[IO.File]::ReadAllText($probe)
$mutations=@{
 'DOC_LINK' = [Environment]::NewLine+'[invalid fixture](missing-file-fixture.md)'
 'DOC_REFERENCE' = [Environment]::NewLine+'AUTHZ-99'
 'DOC_FENCE' = [Environment]::NewLine+([string][char]96+[char]96+[char]96)
}
foreach($code in $mutations.Keys){
    [IO.File]::WriteAllText($probe,$baseline+$mutations[$code],[Text.UTF8Encoding]::new($false))
    $detected=$false
    try{& $checker -Root $fixtureRoot -Quiet}catch{if($_.Exception.Message.Contains($code)){$detected=$true}else{throw}}
    if(-not $detected){throw ('Documentation checker failed negative control: '+$code)}
}
[IO.File]::WriteAllText($probe,$baseline,[Text.UTF8Encoding]::new($false))
$manifestPath=Join-Path $fixtureRoot 'tests/acceptance/manifest.json'
$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$manifest.cases[0].status='passed'
[IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
$detected=$false
try{& $checker -Root $fixtureRoot -Quiet}catch{if($_.Exception.Message.Contains('MANIFEST_STATUS')){$detected=$true}else{throw}}
if(-not $detected){throw 'Documentation checker accepted a false runtime-test claim'}
Write-Output 'Documentation checker: valid fixture plus four adversarial mutations passed.'

