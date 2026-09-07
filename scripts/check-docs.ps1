param([string]$Root = (Split-Path $PSScriptRoot -Parent), [switch]$Quiet, [string]$Report)
$ErrorActionPreference='Stop'
$Root=[IO.Path]::GetFullPath($Root)
$required=@('PROJECT_BRIEF.md','ARCHITECTURE.md','THREAT_MODEL.md','SECURITY_INVARIANTS.md','TRUST_BOUNDARIES.md','COMPETITOR_ARCHITECTURE_REVIEW.md','PKI_DESIGN.md','RESOURCE_MODEL.md','SESSION_AND_REVOCATION_DESIGN.md','BOOTSTRAP_AND_RECOVERY.md','PLATFORM_SUPPORT.md','NETWORK_AND_MULLVAD_DESIGN.md','DNS_DESIGN.md','UPDATE_SECURITY.md','ACCEPTANCE_TEST_PLAN.md','ADR-001-implementation-language.md','ROADMAP.md')
$errors=[Collections.Generic.List[string]]::new()
$documents=@{}
$paths=@(Get-ChildItem -LiteralPath $Root -Filter '*.md' -File)
foreach($directory in @('docs','tests','tools','requirements')){
    $child=Join-Path $Root $directory
    if(Test-Path -LiteralPath $child){$paths+=@(Get-ChildItem -LiteralPath $child -Filter '*.md' -File -Recurse)}
}
foreach($path in $paths){$documents[$path.FullName]=[IO.File]::ReadAllText($path.FullName)}
foreach($name in $required){
    $path=Join-Path $Root $name
    if(-not $documents.ContainsKey($path)){$errors.Add('DOC_REQUIRED: '+$name)}
}
$planPath=Join-Path $Root 'ACCEPTANCE_TEST_PLAN.md'
if(-not $documents.ContainsKey($planPath)){throw ($errors -join [Environment]::NewLine)}
$testIds=@([regex]::Matches($documents[$planPath],'(?m)^\| ([A-Z]+-\d{2}) \|') | ForEach-Object {$_.Groups[1].Value})
if($testIds.Count -ne 91 -or @($testIds | Sort-Object -Unique).Count -ne 91){$errors.Add('TEST_IDS: expected 91 unique planned runtime cases')}
$defined=@{}
foreach($entry in @(@('INV','SECURITY_INVARIANTS.md'),@('TH','THREAT_MODEL.md'),@('CTRL','SECURITY_CONTROL_MATRIX.md'))){
    $path=Join-Path $Root $entry[1]
    if(-not $documents.ContainsKey($path)){$errors.Add('DOC_REQUIRED: '+$entry[1]);continue}
    $defined[$entry[0]]=@([regex]::Matches($documents[$path],'(?m)^\| ('+$entry[0]+'-\d{2}) \|') | ForEach-Object {$_.Groups[1].Value})
}
$prefixes=@($testIds | ForEach-Object {$_ -replace '-\d+$',''} | Sort-Object -Unique)+@('INV','TH','CTRL')
foreach($path in $documents.Keys){
    $body=$documents[$path]
    foreach($match in [regex]::Matches($body,'\]\(([^)]+)\)')){
        $target=$match.Groups[1].Value.Trim('<','>')
        if($target -match '^(https?://|#|mailto:)'){continue}
        $relative=($target -split '#')[0]
        if($relative -and -not (Test-Path -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($path)) $relative))){
            $errors.Add('DOC_LINK: '+[IO.Path]::GetFileName($path)+' -> '+$relative)
        }
    }
    foreach($match in [regex]::Matches($body,'\b([A-Z]+)-(\d{2})(?:[–-](?:([A-Z]+)-)?(\d{2}))?')){
        $prefix=$match.Groups[1].Value
        if($prefix -notin $prefixes){continue}
        $first=[int]$match.Groups[2].Value; $last=$first
        if($match.Groups[4].Success -and ((-not $match.Groups[3].Success) -or $match.Groups[3].Value -eq $prefix)){$last=[int]$match.Groups[4].Value}
        $allowed=$testIds; if($defined.ContainsKey($prefix)){$allowed=$defined[$prefix]}
        foreach($number in $first..$last){
            $id=$prefix+'-'+$number.ToString('00')
            if($id -notin $allowed){$errors.Add('DOC_REFERENCE: '+$id)}
        }
    }
    $fence=[string][char]96+[char]96+[char]96
    if(([regex]::Matches($body,'(?m)^'+[regex]::Escape($fence)).Count % 2) -ne 0){$errors.Add('DOC_FENCE: '+$path)}
}
$manifestPath=Join-Path $Root 'tests/acceptance/manifest.json'
if(-not (Test-Path -LiteralPath $manifestPath)){$errors.Add('MANIFEST: missing')}
else{
    $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $ids=@($manifest.cases | ForEach-Object {$_.id})
    if($ids.Count -ne 91 -or @($ids | Sort-Object -Unique).Count -ne 91 -or @(Compare-Object ($testIds | Sort-Object) ($ids | Sort-Object)).Count -ne 0){$errors.Add('MANIFEST: case IDs differ from canonical plan')}
    foreach($case in $manifest.cases){
        if($case.status -eq 'planned'){continue}
        if($case.status -ne 'implemented' -or $case.earliest_phase -gt $manifest.phase -or -not $case.test_file -or $case.test_name -notmatch '^Test[A-Za-z0-9_]+$'){
            $errors.Add('MANIFEST_STATUS: implemented cases require an eligible phase and executable test reference');continue
        }
        $testPath=[IO.Path]::GetFullPath((Join-Path $Root $case.test_file))
        $prefix=$Root.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
        if(-not $testPath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $testPath)){
            $errors.Add('MANIFEST_STATUS: test source missing or outside repository');continue
        }
        if([IO.File]::ReadAllText($testPath) -notmatch ('func\s+'+[regex]::Escape($case.test_name)+'\s*\(')){$errors.Add('MANIFEST_STATUS: test function missing')}
    }
}
$original=Join-Path $Root 'requirements/PORTICO_MASTER_PROMPT.md'
if(-not (Test-Path -LiteralPath $original) -or (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash -ne '653B502484F8932C9B2A4FAA40B02248C0215407996882E74FBFB3ADEEF6B37F'){
    $errors.Add('REQUIREMENTS_HASH: original brief changed')
}
$result=[ordered]@{required_documents=$required.Count;markdown_documents=$documents.Count;runtime_test_cases=$testIds.Count;planned_runtime_tests=@($manifest.cases|Where-Object status -eq planned).Count;implemented_runtime_tests=@($manifest.cases|Where-Object status -eq implemented).Count;errors=@($errors)}
if($Report){[IO.File]::WriteAllText($Report,($result | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))}
if($errors.Count -gt 0){throw ($errors -join [Environment]::NewLine)}
if(-not $Quiet){$result | ConvertTo-Json -Depth 5}

