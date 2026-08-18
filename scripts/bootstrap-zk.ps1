param(
    [switch]$ForceDownload,
    [switch]$VerifyTranscript
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolsDir = Join-Path $projectRoot 'tools'
$buildDir = Join-Path $projectRoot 'zk\build'
$circomPath = Join-Path $toolsDir 'circom.exe'
$ptauPath = Join-Path $buildDir 'powersOfTau28_hez_final_16.ptau'
$circuitPath = Join-Path $projectRoot 'zk\circuits\train_step.circom'
$expectedCircomSha256 = 'e43f132ee6f0aa79b705beceb59c2a7e6a54d7bdeab917ca34e9fc1951d185e1'
$expectedPtauBlake2b = '6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125'

New-Item -ItemType Directory -Force -Path $toolsDir, $buildDir | Out-Null

if ($ForceDownload -or -not (Test-Path -LiteralPath $circomPath)) {
    Invoke-WebRequest 'https://github.com/iden3/circom/releases/download/v2.2.3/circom-windows-amd64.exe' -OutFile $circomPath
}
$circomSha256 = (Get-FileHash -LiteralPath $circomPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($circomSha256 -ne $expectedCircomSha256) {
    throw "Circom checksum mismatch: $circomSha256"
}

Push-Location $projectRoot
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    & $circomPath $circuitPath --r1cs --wasm --sym --inspect -l (Join-Path $projectRoot 'node_modules') -o $buildDir
    if ($LASTEXITCODE -ne 0) { throw 'Circom compilation failed' }
    $snarkjsPath = Join-Path $projectRoot 'node_modules\.bin\snarkjs.cmd'
    if (-not (Test-Path -LiteralPath $snarkjsPath)) { throw 'Pinned local snarkjs was not installed' }
    & $snarkjsPath r1cs info (Join-Path $buildDir 'train_step.r1cs')
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect R1CS' }

    if ($ForceDownload -or -not (Test-Path -LiteralPath $ptauPath)) {
        Invoke-WebRequest 'https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau' -OutFile $ptauPath
    }
    $actualPtauBlake2b = python -c "import hashlib, pathlib; print(hashlib.blake2b(pathlib.Path(r'$ptauPath').read_bytes()).hexdigest())"
    if ($actualPtauBlake2b.Trim() -ne $expectedPtauBlake2b) {
        throw "Powers-of-Tau BLAKE2b mismatch: $actualPtauBlake2b"
    }
    if ($VerifyTranscript) {
        & $snarkjsPath powersoftau verify $ptauPath
        if ($LASTEXITCODE -ne 0) { throw 'Powers-of-Tau transcript verification failed' }
    }
    else {
        Write-Warning 'Skipped the expensive contribution-by-contribution PoT audit; the downloaded file was matched to the BLAKE2b hash published by iden3/snarkjs. Re-run with -VerifyTranscript for a full local audit.'
    }

    $r1csPath = Join-Path $buildDir 'train_step.r1cs'
    $zkeyPath = Join-Path $buildDir 'train_step.zkey'
    $verificationKeyPath = Join-Path $buildDir 'verification_key.json'
    & $snarkjsPath plonk setup $r1csPath $ptauPath $zkeyPath
    if ($LASTEXITCODE -ne 0) { throw 'PLONK setup failed' }
    & $snarkjsPath zkey export verificationkey $zkeyPath $verificationKeyPath
    if ($LASTEXITCODE -ne 0) { throw 'Verification-key export failed' }
}
finally {
    Pop-Location
}

Write-Output "ZK toolchain ready in $buildDir"
