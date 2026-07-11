# HYDRA-MSG critical-path coverage gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$Manifest = "qa/coverage/critical-paths.tsv"
$CoverageTool = "qa/coverage/enforce_lcov_thresholds.py"
$Audit = "qa/evidence/coverage-mutation-targets.md"

function Require-File {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path $Path -PathType Leaf)) {
        throw "required coverage file missing: $Path"
    }
}

function Require-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (-not (Get-Content $Path -Raw).Contains($Text)) {
        throw "coverage invariant missing from ${Path}: $Text"
    }
}

Require-File $Manifest
Require-File $CoverageTool
Require-File $Audit

$syntaxCheck = @'
import ast
from pathlib import Path
import sys
ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'), filename=sys.argv[1])
'@
$syntaxCheck | python3 - $CoverageTool
if ($LASTEXITCODE -ne 0) { throw "coverage threshold helper failed syntax check" }

foreach ($line in Get-Content $Manifest) {
    $trimmed = $line.Trim()
    if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) { continue }
    $parts = $line.Split('|')
    if ($parts.Count -ne 7) { throw "coverage manifest row must have 7 fields: $line" }
    $id, $coverageClass, $minLine, $minBranch, $sourceFile, $testFile, $requiredTest = $parts
    foreach ($value in @($coverageClass, $minLine, $minBranch, $sourceFile, $testFile, $requiredTest)) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw "coverage manifest row has empty field: $id" }
    }
    Require-File $sourceFile
    Require-File $testFile
    Require-Text $testFile "fn $requiredTest"
    Require-Text $Manifest "$id|"
}

foreach ($required in @(
    "parser/codec branch and negative-path coverage",
    "state-machine replay and skipped-key transition coverage",
    "generation rollback and stale-state rejection",
    "signature verification negative-path coverage",
    "fragment reassembly branch and malformed-input coverage",
    "group membership transition and authorization coverage",
    "group rekey transition and TreeKEM validation coverage"
)) {
    Require-Text $Manifest $required
}

foreach ($required in @(
    "coverage report",
    "critical-path coverage threshold",
    "parser/codec branch coverage",
    "negative-path coverage",
    "state-machine transition coverage",
    "HYDRA_RUN_COVERAGE=1"
)) {
    Require-Text $Audit $required
}

if ($env:HYDRA_RUN_COVERAGE -eq "1") {
    $CoverageToolchain = if ($env:HYDRA_COVERAGE_TOOLCHAIN) { $env:HYDRA_COVERAGE_TOOLCHAIN } else { "nightly" }

    if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
        throw "HYDRA branch coverage requires rustup and a nightly toolchain. Run .\scripts\setup-dev-env.ps1."
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "HYDRA branch coverage requires cargo on PATH. Load the rustup environment or run .\scripts\setup-dev-env.ps1."
    }

    $CoverageRustcVersion = (& rustup run $CoverageToolchain rustc --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "coverage toolchain is unavailable: $CoverageToolchain. Install it with: rustup toolchain install $CoverageToolchain"
    }
    if ($CoverageRustcVersion -notmatch "nightly") {
        throw "HYDRA branch coverage requires nightly Rust. HYDRA_COVERAGE_TOOLCHAIN=$CoverageToolchain selected: $CoverageRustcVersion"
    }

    $InstalledComponents = & rustup component list --toolchain $CoverageToolchain --installed
    if ($LASTEXITCODE -ne 0) { throw "failed to inspect components for coverage toolchain: $CoverageToolchain" }
    if (-not ($InstalledComponents | Select-String -Pattern '^llvm-tools' -Quiet)) {
        Write-Host "==> installing llvm-tools-preview for coverage toolchain: $CoverageToolchain"
        & rustup component add llvm-tools-preview --toolchain $CoverageToolchain
        if ($LASTEXITCODE -ne 0) { throw "failed to install llvm-tools-preview for $CoverageToolchain" }
    }

    & cargo "+$CoverageToolchain" llvm-cov --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "HYDRA_RUN_COVERAGE=1 requires cargo-llvm-cov to be installed. Install with: cargo install cargo-llvm-cov --locked, or run .\scripts\setup-dev-env.ps1" }

    Write-Host "==> branch coverage toolchain: $CoverageRustcVersion"
    New-Item -ItemType Directory -Force -Path "target/coverage" | Out-Null
    & cargo "+$CoverageToolchain" llvm-cov clean --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo llvm-cov clean failed" }
    & cargo "+$CoverageToolchain" llvm-cov --workspace --all-targets --branch --lcov --output-path target/coverage/hydra.lcov
    if ($LASTEXITCODE -ne 0) { throw "cargo llvm-cov lcov failed" }
    python3 $CoverageTool $Manifest target/coverage/hydra.lcov
    if ($LASTEXITCODE -ne 0) { throw "critical-path LCOV threshold enforcement failed" }
    & cargo "+$CoverageToolchain" llvm-cov --workspace --all-targets --branch --html --output-dir target/coverage/html
    if ($LASTEXITCODE -ne 0) { throw "cargo llvm-cov html report failed" }
} else {
    Write-Host "coverage manifest/static gate passed. Set HYDRA_RUN_COVERAGE=1 to generate and enforce LCOV/HTML coverage." -ForegroundColor Green
}
