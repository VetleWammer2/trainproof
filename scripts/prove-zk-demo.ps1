param(
    [string]$OutputDirectory = 'zk\demo-run'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $projectRoot 'zk\build'
if ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $outputDir = [System.IO.Path]::GetFullPath($OutputDirectory)
}
else {
    $outputDir = [System.IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
}
$allowedInProject = [System.IO.Path]::GetFullPath((Join-Path $projectRoot 'zk\demo-run'))
$projectPath = [System.IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$projectPrefix = $projectPath + '\'
if (
    ($outputDir.Equals($projectPath, [System.StringComparison]::OrdinalIgnoreCase) -or
     $outputDir.StartsWith($projectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) -and
    -not $outputDir.Equals($allowedInProject, [System.StringComparison]::OrdinalIgnoreCase)
) {
    throw 'Inside the source repository, ZK output is restricted to the fixed excluded path zk\demo-run. Use an output path outside the repository otherwise.'
}
$privateDir = Join-Path $outputDir 'private'
$publicDir = Join-Path $outputDir 'public'

if (-not (Test-Path -LiteralPath (Join-Path $buildDir 'train_step.zkey'))) {
    throw 'Run scripts\bootstrap-zk.ps1 first.'
}
if (Test-Path -LiteralPath $outputDir) {
    throw "Refusing to overwrite existing ZK demo directory: $outputDir"
}

Push-Location $projectRoot
try {
    node .\zk\scripts\prepare-input.mjs $outputDir .\zk\circuits\train_step.circom
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the private witness' }
    python .\scripts\precommit-zk-demo.py $outputDir
    if ($LASTEXITCODE -ne 0) { throw 'Could not precommit the run inputs before proving' }

    $wasmPath = Join-Path $buildDir 'train_step_js\train_step.wasm'
    $witnessPath = Join-Path $privateDir 'witness.wtns'
    $inputPath = Join-Path $privateDir 'input.json'
    $r1csPath = Join-Path $buildDir 'train_step.r1cs'
    $zkeyPath = Join-Path $buildDir 'train_step.zkey'
    $proofPath = Join-Path $publicDir 'proof.json'
    $publicSignalsPath = Join-Path $publicDir 'public.json'
    $snarkjsPath = Join-Path $projectRoot 'node_modules\.bin\snarkjs.cmd'
    if (-not (Test-Path -LiteralPath $snarkjsPath)) { throw 'Pinned local snarkjs is missing; run bootstrap-zk.ps1' }

    & $snarkjsPath wtns calculate $wasmPath $inputPath $witnessPath
    if ($LASTEXITCODE -ne 0) { throw 'Witness generation failed' }
    & $snarkjsPath wtns check $r1csPath $witnessPath
    if ($LASTEXITCODE -ne 0) { throw 'Witness does not satisfy the R1CS' }
    & $snarkjsPath plonk prove $zkeyPath $witnessPath $proofPath $publicSignalsPath
    if ($LASTEXITCODE -ne 0) { throw 'PLONK proof generation failed' }
    & $snarkjsPath plonk verify (Join-Path $publicDir 'verification_key.json') $publicSignalsPath $proofPath
    if ($LASTEXITCODE -ne 0) { throw 'PLONK proof verification failed' }
    node .\zk\scripts\verify-public.mjs (Join-Path $buildDir 'train_step.sym') $publicSignalsPath (Join-Path $publicDir 'statement.json')
    if ($LASTEXITCODE -ne 0) { throw 'Named public-signal binding failed' }
    python .\scripts\seal-zk-demo.py $outputDir
    if ($LASTEXITCODE -ne 0) { throw 'Could not seal the ZK proof envelope' }
    python .\scripts\verify-zk-demo.py $outputDir
    if ($LASTEXITCODE -ne 0) { throw 'Independent public ZK verification failed after sealing' }
}
finally {
    Pop-Location
}

Write-Output "Valid ZK proof written to $publicDir"
