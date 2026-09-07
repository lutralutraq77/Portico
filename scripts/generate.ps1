param([switch]$Check,[string]$WorkRoot=(Join-Path (Split-Path $PSScriptRoot -Parent) 'work'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'env.ps1') -WorkRoot $WorkRoot
$lock=Get-Content -LiteralPath (Join-Path $PorticoRoot 'tools/toolchain.lock.json') -Raw|ConvertFrom-Json
$suffix=''; if ($IsWindows) { $suffix='.exe' }
$compiler=Join-Path $PorticoWork ('toolchains/protoc-'+$lock.protoc.version+'/bin/protoc'+$suffix)
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Run scripts/bootstrap.ps1 to install the pinned protoc.' }
if ((& $compiler --version) -ne ('libprotoc '+$lock.protoc.version)) { throw 'Wrong protoc version' }
$target=Join-Path $PorticoRoot 'internal/carrierpb'
if ($Check) { $target=Join-Path $PorticoWork ('generated-'+[guid]::NewGuid().ToString('N')) }
[IO.Directory]::CreateDirectory($target)|Out-Null
& $compiler ('--proto_path='+ (Join-Path $PorticoRoot 'proto')) ('--go_out='+$target) --go_opt=paths=source_relative ('--go-grpc_out='+$target) --go-grpc_opt=paths=source_relative (Join-Path $PorticoRoot 'proto/carrier.proto')
if ($LASTEXITCODE -ne 0) { throw 'Carrier code generation failed' }
if ($Check) {
    foreach ($name in @('carrier.pb.go','carrier_grpc.pb.go')) {
        $source=Join-Path $PorticoRoot ('internal/carrierpb/'+$name)
        if (-not (Test-Path -LiteralPath $source) -or (Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath (Join-Path $target $name)).Hash) {
            throw ('Generated carrier code differs: '+$name)
        }
    }
}
Write-Output 'Pinned carrier generation passed.'
