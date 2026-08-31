# HYDRA-MSG LCOV + function coverage + CRAP gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$CriticalManifest = "qa/coverage/critical-functions.tsv"
$QualityTool = "qa/quality/enforce_quality.rs"
$QualityToolDir = "target/qa-tools/coverage"
$QualityToolBin = Join-Path $QualityToolDir "enforce-quality.exe"
$QualityToolTests = Join-Path $QualityToolDir "enforce-quality-tests.exe"
$Audit = "docs/validation/evidence/coverage-mutation-targets.md"
$Lcov = "target/coverage/hydra.lcov"
$FunctionReport = "target/coverage/function-quality.tsv"

function Require-File {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path $Path -PathType Leaf)) { throw "required coverage file missing: $Path" }
}

function Require-Text {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Text)
    if (-not (Get-Content $Path -Raw).Contains($Text)) { throw "coverage invariant missing from ${Path}: $Text" }
}

foreach ($file in @($CriticalManifest, $QualityTool, "qa/quality/lcov.rs", "qa/quality/rust_source.rs", $Audit)) {
    Require-File $file
}

$PythonCoverageHelpers = Get-ChildItem "qa/coverage" -Filter *.py -File -Recurse
if ($PythonCoverageHelpers) {
    $PythonCoverageHelpers | ForEach-Object { Write-Host $_.FullName }
    throw "Python coverage helper found; coverage enforcement must remain Rust-only"
}

foreach ($required in @(
    "Critical cryptographic functions require 100% line and branch coverage",
    "Native production function ranges require at least 85% aggregate line coverage and 65% aggregate branch coverage",
    "Cyclomatic complexity is capped at 12",
    "CRAP is capped at 25",
    "target/coverage/hydra.lcov",
    "target/coverage/function-quality.tsv"
)) {
    Require-Text $Audit $required
}

if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    throw "coverage/CRAP enforcement requires rustc on PATH. Run .\scripts\setup-dev-env.ps1."
}
New-Item -ItemType Directory -Force -Path $QualityToolDir | Out-Null
& rustc --edition=2021 -D warnings --test $QualityTool -o $QualityToolTests
if ($LASTEXITCODE -ne 0) { throw "coverage/CRAP quality helper tests failed to compile" }
& $QualityToolTests
if ($LASTEXITCODE -ne 0) { throw "coverage/CRAP quality helper tests failed" }
& rustc --edition=2021 -D warnings $QualityTool -o $QualityToolBin
if ($LASTEXITCODE -ne 0) { throw "coverage/CRAP quality helper failed to compile" }

foreach ($line in Get-Content $CriticalManifest) {
    $trimmed = $line.Trim()
    if ($trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) { continue }
    $parts = $line.Split('|')
    if ($parts.Count -ne 4) { throw "critical coverage row must have 4 fields: $line" }
    foreach ($value in $parts) {
        if ([string]::IsNullOrWhiteSpace($value)) { throw "critical coverage row has empty field: $line" }
    }
    Require-File $parts[1]
}

if ($env:HYDRA_RUN_COVERAGE -ne "1") {
    Write-Host "coverage/CRAP manifest and helper checks passed. Set HYDRA_RUN_COVERAGE=1 to generate LCOV and enforce thresholds." -ForegroundColor Green
    exit 0
}

$CoverageToolchain = if ($env:HYDRA_COVERAGE_TOOLCHAIN) { $env:HYDRA_COVERAGE_TOOLCHAIN } else { "nightly" }
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) { throw "HYDRA coverage requires rustup" }
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw "HYDRA coverage requires cargo" }
$CoverageRustcVersion = (& rustup run $CoverageToolchain rustc --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "coverage toolchain unavailable: $CoverageToolchain" }
if ($CoverageRustcVersion -notmatch "nightly") { throw "branch coverage requires nightly Rust; selected: $CoverageRustcVersion" }

$InstalledComponents = & rustup component list --toolchain $CoverageToolchain --installed
if ($LASTEXITCODE -ne 0) { throw "failed to inspect coverage toolchain components" }
if (-not ($InstalledComponents | Select-String -Pattern '^llvm-tools' -Quiet)) {
    & rustup component add llvm-tools-preview --toolchain $CoverageToolchain
    if ($LASTEXITCODE -ne 0) { throw "failed to install llvm-tools-preview for $CoverageToolchain" }
}
& cargo "+$CoverageToolchain" llvm-cov --version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "cargo-llvm-cov is required. Run .\scripts\setup-dev-env.ps1." }

Write-Host "==> branch coverage toolchain: $CoverageRustcVersion"
New-Item -ItemType Directory -Force -Path "target/coverage" | Out-Null
& cargo "+$CoverageToolchain" llvm-cov clean --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo llvm-cov clean failed" }
& cargo "+$CoverageToolchain" llvm-cov --workspace --all-targets --branch --lcov --output-path $Lcov
if ($LASTEXITCODE -ne 0) { throw "cargo llvm-cov LCOV run failed" }
& $QualityToolBin $Lcov $CriticalManifest $FunctionReport
if ($LASTEXITCODE -ne 0) { throw "coverage/CC/CRAP threshold enforcement failed" }
# Reuse the just-collected profiling data. Do not execute the workspace tests a second time for HTML.
& cargo "+$CoverageToolchain" llvm-cov report --branch --html --output-dir target/coverage/html
if ($LASTEXITCODE -ne 0) { throw "cargo llvm-cov HTML report failed" }
Write-Host "LCOV/coverage/CC/CRAP checks passed." -ForegroundColor Green
