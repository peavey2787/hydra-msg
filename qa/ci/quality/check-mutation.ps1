# HYDRA-MSG mutation-target gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$Manifest = "qa/mutation/targets.tsv"
$Audit = "qa/evidence/coverage-mutation-targets.md"

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
}

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
    "HYDRA_RUN_MUTATION=1"
)) {
    Require-Text $Audit $required
}

if ($env:HYDRA_RUN_MUTATION -eq "1") {
    cargo mutants --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "HYDRA_RUN_MUTATION=1 requires cargo-mutants to be installed. Install with: cargo install cargo-mutants --locked, or run .\scripts\setup-dev-env.ps1" }
    New-Item -ItemType Directory -Force -Path "target/mutants" | Out-Null
    cargo mutants --workspace --timeout 120 --jobs 1 --output target/mutants
    if ($LASTEXITCODE -ne 0) { throw "cargo-mutants run failed" }
} else {
    Write-Host "mutation manifest/static gate passed. Set HYDRA_RUN_MUTATION=1 to run cargo-mutants." -ForegroundColor Green
}
