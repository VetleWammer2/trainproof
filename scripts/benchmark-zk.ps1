param(
    [int]$Trials = 3,
    [string]$ResultPath = 'benchmarks\results\windows-i7-8700k-2026-08-18.json'
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$circom = Join-Path $projectRoot 'tools\circom.exe'
$node = (Get-Command node -ErrorAction Stop).Source
$python = (Get-Command python -ErrorAction Stop).Source
$snarkjs = Join-Path $projectRoot 'node_modules\snarkjs\build\cli.cjs'
$ptau = Join-Path $projectRoot 'zk\build\powersOfTau28_hez_final_16.ptau'
$legacyPtau = Join-Path $projectRoot 'zk\build\powersOfTau28_hez_final_14.ptau'
$includePath = Join-Path $projectRoot 'node_modules'
$productionCircuit = Join-Path $projectRoot 'zk\circuits\train_step.circom'
$legacyCircuit = Join-Path $projectRoot 'zk\circuits\legacy_train_step_v1.circom'
$workRoot = Join-Path $projectRoot ('zk\benchmark-work\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))

if ($Trials -lt 1) { throw 'Trials must be positive' }
foreach ($path in @($circom, $snarkjs, $ptau, $productionCircuit, $legacyCircuit)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing benchmark prerequisite: $path"
    }
}
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null

function Invoke-MeasuredProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) { throw "Could not start $FilePath" }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $peak = 0L
    do {
        try {
            $process.Refresh()
            $peak = [Math]::Max($peak, [int64]$process.WorkingSet64)
            $peak = [Math]::Max($peak, [int64]$process.PeakWorkingSet64)
        }
        catch [System.InvalidOperationException] {
            # The process may exit between WaitForExit and Refresh.
        }
    } while (-not $process.WaitForExit(10))
    $process.WaitForExit()
    $stopwatch.Stop()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    return [ordered]@{
        elapsedMilliseconds = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
        peakWorkingSetBytes = $peak
        exitCode = $process.ExitCode
        stdout = $stdout
        stderr = $stderr
    }
}

function Assert-Success {
    param([System.Collections.IDictionary]$Measurement, [string]$Label)
    if ($Measurement.exitCode -ne 0) {
        throw "$Label failed with exit code $($Measurement.exitCode): $($Measurement.stderr)$($Measurement.stdout)"
    }
}

function Median {
    param([double[]]$Values)
    $sorted = @($Values | Sort-Object)
    $middle = [Math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2 -eq 1) { return $sorted[$middle] }
    return ($sorted[$middle - 1] + $sorted[$middle]) / 2
}

function File-Size {
    param([string]$Path)
    return (Get-Item -LiteralPath $Path).Length
}

function File-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function File-Blake2b {
    param([string]$Path)
    $digest = & $python -c 'import hashlib, pathlib, sys; print(hashlib.blake2b(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' $Path
    if ($LASTEXITCODE -ne 0) { throw "Could not hash $Path with BLAKE2b" }
    return $digest.Trim().ToLowerInvariant()
}

$expectedPtauBlake2b = '6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125'
$actualPtauBlake2b = File-Blake2b $ptau
if ($actualPtauBlake2b -ne $expectedPtauBlake2b) {
    throw "Powers-of-Tau BLAKE2b mismatch: expected $expectedPtauBlake2b, got $actualPtauBlake2b"
}

$measuredHead = (& git -C $projectRoot rev-parse HEAD).Trim()
$baseMainCommit = (& git -C $projectRoot merge-base HEAD origin/main).Trim()
$branch = (& git -C $projectRoot branch --show-current).Trim()
$worktreeStatus = (& git -C $projectRoot status --porcelain=v1 --untracked-files=all | Out-String).Trim()
$sourceHashes = [ordered]@{}
foreach ($relativePath in @(
    'zk/circuits/train_step.circom',
    'zk/circuits/legacy_train_step_v1.circom',
    'zk/scripts/prepare-input.mjs',
    'zk/scripts/prepare-legacy-input.mjs',
    'src/trainproof/fixed_point.py',
    'scripts/fixed-point-reference.py',
    'scripts/benchmark-zk.ps1',
    'scripts/verify-zk-demo.py',
    'src/trainproof/zk.py',
    'package-lock.json',
    'pyproject.toml'
)) {
    $sourceHashes[$relativePath] = File-Sha256 (Join-Path $projectRoot $relativePath)
}

$profiles = @(
    [ordered]@{ id = 'legacy_integer_v1_n1'; kind = 'legacy'; n = 1 },
    [ordered]@{ id = 'fixed_point_v2_n1'; kind = 'fixed'; n = 1 },
    [ordered]@{ id = 'fixed_point_v2_n2'; kind = 'fixed'; n = 2 },
    [ordered]@{ id = 'fixed_point_v2_n4'; kind = 'fixed'; n = 4 }
)
$profileResults = @()
$capacityChecks = @()
$sourceText = [System.IO.File]::ReadAllText($productionCircuit)
$mainMarker = 'TrainSteps(4, 2, 4);'
if (-not $sourceText.Contains($mainMarker)) {
    throw 'Production circuit no longer contains the expected N=4 profile marker'
}

foreach ($profile in $profiles) {
    $profileDir = Join-Path $workRoot $profile.id
    $buildDir = Join-Path $profileDir 'build'
    $inputDir = Join-Path $profileDir 'input'
    New-Item -ItemType Directory -Force -Path $buildDir, $inputDir | Out-Null

    if ($profile.kind -eq 'legacy') {
        $circuitPath = $legacyCircuit
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($legacyCircuit)
    }
    else {
        $circuitPath = Join-Path $profileDir ("fixed_train_steps_n$($profile.n).circom")
        $variantText = $sourceText.Replace(
            $mainMarker,
            "TrainSteps($($profile.n), 2, 4);"
        )
        [System.IO.File]::WriteAllText(
            $circuitPath,
            $variantText,
            [System.Text.UTF8Encoding]::new($false)
        )
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($circuitPath)
    }

    $compile = Invoke-MeasuredProcess -FilePath $circom -Arguments @(
        $circuitPath, '--r1cs', '--wasm', '--sym', '--inspect',
        '-l', $includePath, '-o', $buildDir
    ) -WorkingDirectory $projectRoot
    Assert-Success $compile "compile $($profile.id)"

    $r1cs = Join-Path $buildDir "$baseName.r1cs"
    $wasm = Join-Path $buildDir "${baseName}_js\$baseName.wasm"
    $sym = Join-Path $buildDir "$baseName.sym"
    $zkey = Join-Path $buildDir "$baseName.zkey"
    $verificationKey = Join-Path $buildDir 'verification_key.json'
    $r1csInfo = Invoke-MeasuredProcess -FilePath $node -Arguments @(
        $snarkjs, 'r1cs', 'info', $r1cs
    ) -WorkingDirectory $projectRoot
    Assert-Success $r1csInfo "R1CS inspection $($profile.id)"
    $infoText = $r1csInfo.stdout + $r1csInfo.stderr
    $r1csPatterns = [ordered]@{
        constraints = '# of Constraints:\s+(\d+)'
        wires = '# of Wires:\s+(\d+)'
        publicInputs = '# of Public Inputs:\s+(\d+)'
        privateInputs = '# of Private Inputs:\s+(\d+)'
    }
    $r1csValues = [ordered]@{}
    foreach ($name in $r1csPatterns.Keys) {
        $match = [regex]::Match($infoText, $r1csPatterns[$name])
        if (-not $match.Success) {
            throw "Could not parse $name from R1CS inspection for $($profile.id): $infoText"
        }
        $r1csValues[$name] = [int]$match.Groups[1].Value
    }
    $constraints = $r1csValues.constraints
    $wires = $r1csValues.wires
    $publicInputs = $r1csValues.publicInputs
    $privateInputs = $r1csValues.privateInputs

    if ($profile.kind -eq 'legacy') {
        $prepare = Invoke-MeasuredProcess -FilePath $node -Arguments @(
            (Join-Path $projectRoot 'zk\scripts\prepare-legacy-input.mjs'),
            $inputDir,
            $circuitPath
        ) -WorkingDirectory $projectRoot
        $inputPath = Join-Path $inputDir 'input.json'
    }
    else {
        $prepare = Invoke-MeasuredProcess -FilePath $node -Arguments @(
            (Join-Path $projectRoot 'zk\scripts\prepare-input.mjs'),
            $inputDir,
            $circuitPath,
            [string]$profile.n
        ) -WorkingDirectory $projectRoot
        $inputPath = Join-Path $inputDir 'private\input.json'
    }
    Assert-Success $prepare "input preparation $($profile.id)"

    $setup = Invoke-MeasuredProcess -FilePath $node -Arguments @(
        $snarkjs, 'plonk', 'setup', $r1cs, $ptau, $zkey
    ) -WorkingDirectory $projectRoot
    Assert-Success $setup "PLONK setup $($profile.id)"
    $setupText = $setup.stdout + $setup.stderr
    $plonkMatch = [regex]::Match($setupText, 'Plonk constraints:\s+(\d+)')
    if (-not $plonkMatch.Success) {
        throw "Could not parse PLONK constraints for $($profile.id): $setupText"
    }
    $plonkConstraints = [int]$plonkMatch.Groups[1].Value

    if ($profile.id -eq 'fixed_point_v2_n4') {
        if (Test-Path -LiteralPath $legacyPtau -PathType Leaf) {
            $legacyCapacityZkey = Join-Path $buildDir 'power14-capacity-probe.zkey'
            $capacityProbe = Invoke-MeasuredProcess -FilePath $node -Arguments @(
                $snarkjs, 'plonk', 'setup', $r1cs, $legacyPtau, $legacyCapacityZkey
            ) -WorkingDirectory $projectRoot
            $capacityOutput = ($capacityProbe.stdout + $capacityProbe.stderr).Trim()
            if ($capacityProbe.exitCode -eq 0 -or $capacityOutput -notmatch '53313\s*>\s*2\*\*14') {
                throw "Expected the N=4 power-14 setup capacity rejection, got: $capacityOutput"
            }
            $capacityChecks += [ordered]@{
                profile = $profile.id
                executed = $true
                command = 'snarkjs plonk setup <n4.r1cs> powersOfTau28_hez_final_14.ptau <zkey>'
                exitCode = $capacityProbe.exitCode
                elapsedMilliseconds = $capacityProbe.elapsedMilliseconds
                peakWorkingSetBytes = $capacityProbe.peakWorkingSetBytes
                observedPlonkConstraints = $plonkConstraints
                maximumSupportedConstraints = 16384
                output = $capacityOutput
                powersOfTauFile = [System.IO.Path]::GetFileName($legacyPtau)
                powersOfTauBlake2b = File-Blake2b $legacyPtau
                powersOfTauSourceUrl = 'https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_14.ptau'
            }
        }
        else {
            $capacityChecks += [ordered]@{
                profile = $profile.id
                executed = $false
                reason = 'The superseded power-14 file was not present; compare observedPlonkConstraints with 16384.'
                observedPlonkConstraints = $plonkConstraints
                maximumSupportedConstraints = 16384
            }
        }
    }
    $exportVk = Invoke-MeasuredProcess -FilePath $node -Arguments @(
        $snarkjs, 'zkey', 'export', 'verificationkey', $zkey, $verificationKey
    ) -WorkingDirectory $projectRoot
    Assert-Success $exportVk "verification-key export $($profile.id)"

    $trialResults = @()
    for ($trial = 1; $trial -le $Trials; $trial++) {
        $witness = Join-Path $profileDir "witness-$trial.wtns"
        $proof = Join-Path $profileDir "proof-$trial.json"
        $public = Join-Path $profileDir "public-$trial.json"
        $witnessMeasurement = Invoke-MeasuredProcess -FilePath $node -Arguments @(
            $snarkjs, 'wtns', 'calculate', $wasm, $inputPath, $witness
        ) -WorkingDirectory $projectRoot
        Assert-Success $witnessMeasurement "witness trial $trial for $($profile.id)"
        $check = Invoke-MeasuredProcess -FilePath $node -Arguments @(
            $snarkjs, 'wtns', 'check', $r1cs, $witness
        ) -WorkingDirectory $projectRoot
        Assert-Success $check "witness check trial $trial for $($profile.id)"
        $prove = Invoke-MeasuredProcess -FilePath $node -Arguments @(
            $snarkjs, 'plonk', 'prove', $zkey, $witness, $proof, $public
        ) -WorkingDirectory $projectRoot
        Assert-Success $prove "proof trial $trial for $($profile.id)"
        $verify = Invoke-MeasuredProcess -FilePath $node -Arguments @(
            $snarkjs, 'plonk', 'verify', $verificationKey, $public, $proof
        ) -WorkingDirectory $projectRoot
        Assert-Success $verify "verification trial $trial for $($profile.id)"
        if (($verify.stdout + $verify.stderr) -notmatch 'OK!') {
            throw "Verifier did not report OK for $($profile.id) trial $trial"
        }
        $trialResults += [ordered]@{
            trial = $trial
            witness = [ordered]@{
                elapsedMilliseconds = $witnessMeasurement.elapsedMilliseconds
                peakWorkingSetBytes = $witnessMeasurement.peakWorkingSetBytes
                sizeBytes = File-Size $witness
            }
            prove = [ordered]@{
                elapsedMilliseconds = $prove.elapsedMilliseconds
                peakWorkingSetBytes = $prove.peakWorkingSetBytes
            }
            verify = [ordered]@{
                elapsedMilliseconds = $verify.elapsedMilliseconds
                peakWorkingSetBytes = $verify.peakWorkingSetBytes
            }
            proofJsonSizeBytes = File-Size $proof
            publicSignalsSizeBytes = File-Size $public
        }
    }

    $profileResults += [ordered]@{
        id = $profile.id
        relationClass = if ($profile.kind -eq 'legacy') { 'bounded unsigned scalar integer transition v1' } else { 'bounded signed fixed-point vector chain v2' }
        n = $profile.n
        circuitSha256 = File-Sha256 $circuitPath
        r1csSha256 = File-Sha256 $r1cs
        constraints = $constraints
        constraintsPerTransition = [Math]::Round($constraints / $profile.n, 3)
        plonkConstraints = $plonkConstraints
        wires = $wires
        publicInputs = $publicInputs
        privateInputs = $privateInputs
        compile = [ordered]@{
            elapsedMilliseconds = $compile.elapsedMilliseconds
            peakWorkingSetBytes = $compile.peakWorkingSetBytes
        }
        setup = [ordered]@{
            elapsedMilliseconds = $setup.elapsedMilliseconds
            peakWorkingSetBytes = $setup.peakWorkingSetBytes
        }
        artifactSizesBytes = [ordered]@{
            circuit = File-Size $circuitPath
            r1cs = File-Size $r1cs
            wasm = File-Size $wasm
            sym = File-Size $sym
            zkey = File-Size $zkey
            verificationKey = File-Size $verificationKey
        }
        trials = $trialResults
        medians = [ordered]@{
            witnessMilliseconds = Median @($trialResults | ForEach-Object { $_.witness.elapsedMilliseconds })
            witnessPeakWorkingSetBytes = Median @($trialResults | ForEach-Object { $_.witness.peakWorkingSetBytes })
            proveMilliseconds = Median @($trialResults | ForEach-Object { $_.prove.elapsedMilliseconds })
            provePeakWorkingSetBytes = Median @($trialResults | ForEach-Object { $_.prove.peakWorkingSetBytes })
            verifyMilliseconds = Median @($trialResults | ForEach-Object { $_.verify.elapsedMilliseconds })
            verifyPeakWorkingSetBytes = Median @($trialResults | ForEach-Object { $_.verify.peakWorkingSetBytes })
            proofJsonSizeBytes = Median @($trialResults | ForEach-Object { $_.proofJsonSizeBytes })
        }
    }
}

$demoRun = Join-Path $projectRoot 'zk\demo-run'
$demoCertificate = Join-Path $demoRun 'public\certificate.json'
if (Test-Path -LiteralPath $demoCertificate -PathType Leaf) {
    $fixtureHashes = [ordered]@{}
    $publicFixtureRoot = Join-Path $demoRun 'public'
    Get-ChildItem -LiteralPath $publicFixtureRoot -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            $relativeFixturePath = [System.IO.Path]::GetRelativePath(
                $publicFixtureRoot,
                $_.FullName
            ).Replace('\', '/')
            $fixtureHashes[$relativeFixturePath] = File-Sha256 $_.FullName
        }
    $publicVerifier = Invoke-MeasuredProcess -FilePath $python -Arguments @(
        (Join-Path $projectRoot 'scripts\verify-zk-demo.py'), $demoRun
    ) -WorkingDirectory $projectRoot
    Assert-Success $publicVerifier 'end-to-end public verifier'
    if (($publicVerifier.stdout + $publicVerifier.stderr) -notmatch '"valid": true') {
        throw 'End-to-end public verifier did not report a valid certificate'
    }
    $publicVerifierResult = [ordered]@{
        executed = $true
        samples = 1
        elapsedMilliseconds = $publicVerifier.elapsedMilliseconds
        primaryProcessPeakWorkingSetBytes = $publicVerifier.peakWorkingSetBytes
        fixturePublicFileSha256 = $fixtureHashes
        note = 'This source-to-R1CS-to-verification-key public verifier includes child-process compilation and setup. Its wall time is end to end; the primary Python working set does not include child-process memory.'
    }
}
else {
    $publicVerifierResult = [ordered]@{
        executed = $false
        reason = 'zk/demo-run/public/certificate.json was not present'
    }
}

$operatingSystem = Get-CimInstance Win32_OperatingSystem
$processor = Get-CimInstance Win32_Processor | Select-Object -First 1
$result = [ordered]@{
    schema = 'trainproof-zk-benchmark/v1'
    measuredAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    measurementNotes = @(
        'Each timed command ran as a fresh primary process; peakWorkingSetBytes is the maximum polled primary-process WorkingSet64/PeakWorkingSet64 at 10 ms intervals.',
        'Witnesses were checked outside the reported witness timing. Input generation was outside all timed phases.',
        'Witness, prove, and verify medians cover the configured number of fresh CLI processes (three by default); OS caches were not cleared and profile order was fixed.',
        'Compile and PLONK setup are single samples per profile, not medians.',
        'verifyMilliseconds is raw snarkjs PLONK verification; endToEndPublicVerifier separately measures the project verifier when a sealed demo fixture is present.',
        'proofJsonSizeBytes is the UTF-8 snarkjs JSON serialization, not a canonical binary or on-chain encoding.',
        'The legacy v1 and fixed-point v2 rows are intentionally non-equivalent relations and compare arithmetic/profile cost, not identical semantics.'
    )
    source = [ordered]@{
        repository = 'https://github.com/VetleWammer2/trainproof'
        baseMainCommit = $baseMainCommit
        measuredImplementationCommit = $measuredHead
        branch = $branch
        worktreeDirtyDuringMeasurement = -not [string]::IsNullOrWhiteSpace($worktreeStatus)
        relevantFileSha256 = $sourceHashes
    }
    machine = [ordered]@{
        os = $operatingSystem.Caption
        osVersion = $operatingSystem.Version
        architecture = $operatingSystem.OSArchitecture
        cpu = $processor.Name.Trim()
        physicalCores = $processor.NumberOfCores
        logicalProcessors = $processor.NumberOfLogicalProcessors
        totalMemoryBytes = [int64]$operatingSystem.TotalVisibleMemorySize * 1024
    }
    tools = [ordered]@{
        circom = '2.2.3'
        circomSha256 = File-Sha256 $circom
        node = (& $node --version).Trim()
        python = (& $python --version 2>&1).Trim()
        npm = (& npm --version).Trim()
        snarkjs = '0.7.6'
        circomlib = '2.0.5'
        circomlibjs = '0.1.7'
        powersOfTauFile = [System.IO.Path]::GetFileName($ptau)
        powersOfTauExpectedBlake2b = $expectedPtauBlake2b
        powersOfTauActualBlake2b = $actualPtauBlake2b
        powersOfTauDigestMatched = $true
        powersOfTauFullTranscriptVerificationPerformed = $false
    }
    capacityChecks = $capacityChecks
    endToEndPublicVerifier = $publicVerifierResult
    profiles = $profileResults
}

$resolvedResult = if ([System.IO.Path]::IsPathRooted($ResultPath)) {
    [System.IO.Path]::GetFullPath($ResultPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $projectRoot $ResultPath))
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $resolvedResult) | Out-Null
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resolvedResult -Encoding utf8
Write-Output "Benchmark results written to $resolvedResult"
