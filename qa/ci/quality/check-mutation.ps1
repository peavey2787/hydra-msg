# HYDRA-MSG mutation-target gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$Manifest = "qa/mutation/targets.tsv"
$Audit = "docs/validation/evidence/coverage-mutation-targets.md"
$OutputDir = "target/mutants"
$MutationFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

function Require-File {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path $Path -PathType Leaf)) {
        throw "required mutation file missing: $Path"
    }
}

function Require-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (-not (Get-Content $Path -Raw).Contains($Text)) {
        throw "mutation invariant missing from ${Path}: $Text"
    }
}

Require-File $Manifest
Require-File $Audit

foreach ($line in Get-Content $Manifest) {
    $trimmed = $line.Trim()
    if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) { continue }
    $parts = $line.Split('|')
    if ($parts.Count -ne 6) { throw "mutation manifest row must have 6 fields: $line" }
    $id, $risk, $sourceFile, $testFile, $requiredTest, $focus = $parts
    foreach ($value in @($risk, $sourceFile, $testFile, $requiredTest, $focus)) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw "mutation manifest row has empty field: $id" }
    }
    Require-File $sourceFile
    Require-File $testFile
    Require-Text $testFile "fn $requiredTest"
    Require-Text $Manifest "$id|"
    [void]$MutationFiles.Add($sourceFile)
}

if ($MutationFiles.Count -eq 0) { throw "mutation manifest contains no source targets" }

foreach ($required in @(
    "replay-checks|",
    "domain-separation-labels|",
    "generation-rollback-checks|",
    "signature-verification|",
    "fragment-reassembly|",
    "group-membership-rekey|",
    "group-treekem-rekey|"
)) {
    Require-Text $Manifest $required
}

foreach ($required in @(
    "Mutation testing target",
    "replay checks",
    "domain separation labels",
    "generation rollback checks",
    "signature verification",
    "fragment reassembly",
    "group membership/rekey rules",
    "baseline-derived timeout",
    "HYDRA_RUN_MUTATION=1"
)) {
    Require-Text $Audit $required
}

if ($env:HYDRA_RUN_MUTATION -eq "1") {
    cargo mutants --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "HYDRA_RUN_MUTATION=1 requires cargo-mutants to be installed. Install with: cargo install cargo-mutants --locked, or run .\scripts\setup-dev-env.ps1" }

    $mutationBaseline = if ($env:HYDRA_MUTATION_BASELINE) { $env:HYDRA_MUTATION_BASELINE } else { "run" }
    $timeoutMultiplier = if ($env:HYDRA_MUTATION_TIMEOUT_MULTIPLIER) { $env:HYDRA_MUTATION_TIMEOUT_MULTIPLIER } else { "2" }
    $minimumTestTimeout = if ($env:HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT) { $env:HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT } else { "120" }
    $mutationTimeout = if ($env:HYDRA_MUTATION_TIMEOUT) { $env:HYDRA_MUTATION_TIMEOUT } else { "1200" }
    $mutationJobs = if ($env:HYDRA_MUTATION_JOBS) { $env:HYDRA_MUTATION_JOBS } else { "1" }

    $parsedMultiplier = 0.0
    if (-not [double]::TryParse($timeoutMultiplier, [Globalization.NumberStyles]::AllowDecimalPoint, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsedMultiplier) -or $parsedMultiplier -le 0) {
        throw "HYDRA_MUTATION_TIMEOUT_MULTIPLIER must be a positive number, got: $timeoutMultiplier"
    }
    $parsedMinimum = 0
    if (-not [int]::TryParse($minimumTestTimeout, [ref]$parsedMinimum) -or $parsedMinimum -le 0) {
        throw "HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT must be a positive integer, got: $minimumTestTimeout"
    }
    $parsedTimeout = 0
    if (-not [int]::TryParse($mutationTimeout, [ref]$parsedTimeout) -or $parsedTimeout -le 0) {
        throw "HYDRA_MUTATION_TIMEOUT must be a positive integer, got: $mutationTimeout"
    }
    $parsedJobs = 0
    if (-not [int]::TryParse($mutationJobs, [ref]$parsedJobs) -or $parsedJobs -le 0) {
        throw "HYDRA_MUTATION_JOBS must be a positive integer, got: $mutationJobs"
    }
    if ($mutationBaseline -notin @("run", "skip")) {
        throw "HYDRA_MUTATION_BASELINE must be run or skip, got: $mutationBaseline"
    }

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    $arguments = @(
        "mutants",
        "--jobs", $mutationJobs,
        "--output", $OutputDir
    )
    if ($mutationBaseline -eq "skip") {
        $arguments += @("--baseline=skip", "--timeout", $mutationTimeout)
    } else {
        $arguments += @(
            "--timeout-multiplier", $timeoutMultiplier,
            "--minimum-test-timeout", $minimumTestTimeout
        )
    }
    foreach ($sourceFile in ($MutationFiles | Sort-Object)) {
        $arguments += @("--file", $sourceFile)
    }

    Write-Host "Mutation targets:"
    foreach ($sourceFile in ($MutationFiles | Sort-Object)) { Write-Host "  - $sourceFile" }
    if ($mutationBaseline -eq "skip") {
        Write-Host "Mutation baseline: skipped by explicit request"
        Write-Host "Mutation timeout policy: fixed ${mutationTimeout}s per mutant"
    } else {
        Write-Host "Mutation baseline: required"
        Write-Host "Mutation timeout policy: baseline-derived x$timeoutMultiplier, minimum ${minimumTestTimeout}s"
    }
    Write-Host "Mutation jobs: $mutationJobs"
    & cargo @arguments
    if ($LASTEXITCODE -ne 0) { throw "cargo-mutants run failed" }
} else {
    Write-Host "mutation manifest/static gate passed. Set HYDRA_RUN_MUTATION=1 to run cargo-mutants." -ForegroundColor Green
}
