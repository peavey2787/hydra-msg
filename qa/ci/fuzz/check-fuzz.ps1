# HYDRA-MSG deterministic fuzz-smoke gate plus optional coverage-guided cargo-fuzz campaigns.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

if (-not $env:HYDRA_FUZZ_CASES) {
    $env:HYDRA_FUZZ_CASES = "8"
}

$DeterministicExitCode = 0

if ($env:HYDRA_CI_EPHEMERAL_LOCK_REFRESH -eq "1") {
    cargo run -p hydra-fuzz-gate --
    $DeterministicExitCode = $LASTEXITCODE
} else {
    cargo run --locked -p hydra-fuzz-gate --
    $DeterministicExitCode = $LASTEXITCODE
}
if ($DeterministicExitCode -ne 0) {
    exit $DeterministicExitCode
}

if ($env:HYDRA_RUN_COVERAGE_GUIDED_FUZZ -ne "1") {
    Write-Host "coverage-guided fuzz campaigns skipped; set HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1 to run them"
    exit 0
}

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw "HYDRA coverage-guided fuzzing requires rustup and a nightly Rust toolchain. Install nightly with: rustup toolchain install nightly"
}

function Assert-PositiveIntegerText {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $Parsed = 0
    if (-not [int]::TryParse($Value, [ref]$Parsed) -or $Parsed -le 0) {
        throw "$Name must be a positive integer, got: $Value"
    }
}

$FuzzMode = if ($env:HYDRA_FUZZ_MODE) { $env:HYDRA_FUZZ_MODE } else { "smoke" }
switch ($FuzzMode) {
    "smoke" {
        $FastBudgetKind = "runs"
        $FastBudget = if ($env:HYDRA_COVERAGE_FUZZ_RUNS) { $env:HYDRA_COVERAGE_FUZZ_RUNS } else { "256" }
        $StatefulBudgetKind = "runs"
        $StatefulBudget = if ($env:HYDRA_STATEFUL_FUZZ_RUNS) { $env:HYDRA_STATEFUL_FUZZ_RUNS } else { "256" }
    }
    "overnight" {
        $FastBudgetKind = "seconds"
        $FastBudget = if ($env:HYDRA_COVERAGE_FUZZ_SECONDS) { $env:HYDRA_COVERAGE_FUZZ_SECONDS } else { "900" }
        $StatefulBudgetKind = "seconds"
        $StatefulBudget = if ($env:HYDRA_STATEFUL_FUZZ_SECONDS) { $env:HYDRA_STATEFUL_FUZZ_SECONDS } else { "300" }
    }
    "deep" {
        $FastBudgetKind = "runs"
        $FastBudget = if ($env:HYDRA_COVERAGE_FUZZ_RUNS) { $env:HYDRA_COVERAGE_FUZZ_RUNS } else { "100000" }
        $StatefulBudgetKind = "runs"
        $StatefulBudget = if ($env:HYDRA_STATEFUL_FUZZ_RUNS) { $env:HYDRA_STATEFUL_FUZZ_RUNS } else { "1000" }
    }
    default {
        throw "HYDRA_FUZZ_MODE must be smoke, overnight, or deep; got: $FuzzMode"
    }
}

Assert-PositiveIntegerText "fast fuzz budget" $FastBudget
Assert-PositiveIntegerText "stateful fuzz budget" $StatefulBudget

$FuzzToolchain = if ($env:HYDRA_FUZZ_TOOLCHAIN) { $env:HYDRA_FUZZ_TOOLCHAIN } else { "nightly" }
$FuzzDir = Join-Path $RepoRoot "qa/fuzz/cargo-fuzz"
$FuzzManifest = Join-Path $FuzzDir "Cargo.toml"
$EvidenceDir = if ($env:HYDRA_COVERAGE_FUZZ_EVIDENCE_DIR) { $env:HYDRA_COVERAGE_FUZZ_EVIDENCE_DIR } else { "target/hydra-fuzz-evidence" }
$EvidenceRoot = if ([System.IO.Path]::IsPathRooted($EvidenceDir)) {
    $EvidenceDir
} else {
    Join-Path $RepoRoot $EvidenceDir
}

if (-not (Test-Path -LiteralPath $FuzzManifest -PathType Leaf)) {
    throw "HYDRA cargo-fuzz manifest is missing: $FuzzManifest"
}

$FuzzRustcVersion = (& rustup run $FuzzToolchain rustc --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "HYDRA coverage-guided fuzzing requires the selected Rust toolchain '$FuzzToolchain'. Install it with: rustup toolchain install $FuzzToolchain`n$FuzzRustcVersion"
}
if ($FuzzRustcVersion -notmatch "nightly") {
    throw "HYDRA coverage-guided fuzzing requires nightly Rust. HYDRA_FUZZ_TOOLCHAIN=$FuzzToolchain selected: $FuzzRustcVersion"
}

$PreviousRustupToolchain = $env:RUSTUP_TOOLCHAIN
$env:RUSTUP_TOOLCHAIN = $FuzzToolchain
try {
    cargo fuzz --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-fuzz is required for HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1. Install it with: cargo install cargo-fuzz --locked"
    }
} finally {
    if ($null -eq $PreviousRustupToolchain) {
        Remove-Item Env:RUSTUP_TOOLCHAIN -ErrorAction SilentlyContinue
    } else {
        $env:RUSTUP_TOOLCHAIN = $PreviousRustupToolchain
    }
}

$FastTargets = @(
    "envelope_header_decoding",
    "protected_record_decoding",
    "message_codec",
    "storage_backup_chunk_parser",
    "contact_card_parser",
    "handshake_offer_answer_parser",
    "lobby_invite_parser",
    "anonymous_auth_token_parser",
    "fragment_reassembly",
    "session_receive_state_machine",
    "group_commit_message_parser"
)
$StatefulTargets = @(
    "message_stateful_flow"
)

function Invoke-FuzzTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][ValidateSet("runs", "seconds")][string]$BudgetKind,
        [Parameter(Mandatory = $true)][string]$Budget
    )

    $BudgetArgument = if ($BudgetKind -eq "runs") { "-runs=$Budget" } else { "-max_total_time=$Budget" }
    Write-Host "==> coverage-guided fuzz target: $Target mode=$FuzzMode $BudgetKind=$Budget"
    $TargetEvidenceDir = Join-Path $EvidenceRoot $Target
    New-Item -ItemType Directory -Force -Path $TargetEvidenceDir | Out-Null
    cargo fuzz run --fuzz-dir $FuzzDir $Target -- $BudgetArgument "-print_final_stats=1" "-artifact_prefix=$TargetEvidenceDir/"
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Write-Host "Coverage-guided fuzz mode: $FuzzMode"
Write-Host "Coverage-guided fuzz toolchain: $FuzzToolchain ($FuzzRustcVersion)"
Write-Host "Fast target budget: $FastBudgetKind=$FastBudget"
Write-Host "Stateful target budget: $StatefulBudgetKind=$StatefulBudget"
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

try {
    $env:RUSTUP_TOOLCHAIN = $FuzzToolchain
    Write-Host "==> preflight: compile all coverage-guided fuzz targets"
    cargo fuzz build --fuzz-dir $FuzzDir
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    foreach ($Target in $FastTargets) {
        Invoke-FuzzTarget $Target $FastBudgetKind $FastBudget
    }
    foreach ($Target in $StatefulTargets) {
        Invoke-FuzzTarget $Target $StatefulBudgetKind $StatefulBudget
    }
} finally {
    if ($null -eq $PreviousRustupToolchain) {
        Remove-Item Env:RUSTUP_TOOLCHAIN -ErrorAction SilentlyContinue
    } else {
        $env:RUSTUP_TOOLCHAIN = $PreviousRustupToolchain
    }
}

@"
HYDRA coverage-guided fuzz evidence

Mode: $FuzzMode
Rust toolchain: $FuzzToolchain

Fast targets ($FastBudgetKind=$FastBudget):
$($FastTargets -join "`n")

Stateful targets ($StatefulBudgetKind=$StatefulBudget):
$($StatefulTargets -join "`n")

Generated by: qa/ci/fuzz/check-fuzz.ps1
"@ | Set-Content -Path (Join-Path $EvidenceRoot "README.txt")
