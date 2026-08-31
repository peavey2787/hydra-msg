# HYDRA-MSG tests-only validation runner.
# Runs workspace tests plus non-example static validation gates.
# Runnable examples and browser package checks live in qa\ci\core\check-examples.ps1.

[CmdletBinding()]
param(
    [switch]$CheckFormatOnly,
    [switch]$SkipVectors,
    [switch]$SkipReleaseStatic,
    [switch]$FromPrivacy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$LockBackup = $null
if ($env:HYDRA_CI_EPHEMERAL_LOCK_REFRESH -eq "1") {
    New-Item -ItemType Directory -Force -Path "target/ci-logs" | Out-Null
    $LockBackup = "target/ci-logs/Cargo.lock.committed"
    Copy-Item -LiteralPath "Cargo.lock" -Destination $LockBackup -Force
}

function Restore-CommittedLockForPolicy {
    if ($LockBackup -and (Test-Path -LiteralPath $LockBackup)) {
        Copy-Item -LiteralPath $LockBackup -Destination "Cargo.lock" -Force
    }
}
if ($LockBackup) {
    trap {
        Restore-CommittedLockForPolicy
        throw $_
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    # PowerShell-only steps may not set the native-process automatic variable at all,
    # especially when this runner starts at a resumed static gate under StrictMode.
    # Reset it for each step; native commands still overwrite it with their exit code.
    $global:LASTEXITCODE = 0
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Invoke-LockGate {
    Write-Host ""
    Write-Host "==> lock-file checks" -ForegroundColor Cyan
    python3 .\qa\ci\policy\check-workspace-lock.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    python3 .\qa\ci\policy\check-vector-lock-conflicts.py Cargo.lock qa/tools/vector-gen/Cargo.lock
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "lock-file checks passed." -ForegroundColor Green
}

function Invoke-DocsGate {
    Write-Host ""
    Write-Host "==> docs/path/stale-term checks" -ForegroundColor Cyan
    .\qa\ci\policy\check-docs.ps1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if (-not $FromPrivacy) {
    if ($env:HYDRA_CI_EPHEMERAL_LOCK_REFRESH -eq "1") {
        Invoke-Step "cargo metadata" { cargo metadata --format-version 1 --no-deps | Out-Null }
    } else {
        Invoke-Step "cargo metadata --locked" { cargo metadata --locked --format-version 1 --no-deps | Out-Null }
    }

    Invoke-Step "cargo fmt --check" { cargo fmt --all -- --check }
    Invoke-Step "cargo test --workspace --all-targets" { cargo test --workspace --all-targets }
    $env:HYDRA_WORKSPACE_TESTS_ALREADY_RAN = "1"
    Invoke-Step "cargo clippy --workspace --all-targets -- -D warnings" {
        cargo clippy --workspace --all-targets -- -D warnings
    }
    Invoke-Step "supply-chain advisory/license checks" { .\qa\ci\security\check-supply-chain.ps1 }
    Invoke-Step "rust file size ownership checks" { .\qa\ci\policy\check-rust-file-sizes.ps1 }
    Invoke-Step "test quality structural checks" { python3 .\qa\ci\quality\check-test-quality.py }
    Invoke-Step "cyclomatic complexity CC <= 12" { .\qa\ci\quality\check-complexity.ps1 }
} else {
    Write-Host "Resuming tests/static validation at privacy invariant checks." -ForegroundColor Yellow
    $env:HYDRA_WORKSPACE_TESTS_ALREADY_RAN = "1"
}
Invoke-Step "privacy invariant checks" { .\qa\ci\security\check-privacy-invariants.ps1 }
Invoke-Step "resource-exhaustion/DoS limit checks" { .\qa\ci\security\check-resource-limits.ps1 }
Invoke-Step "crash-consistency matrix checks" { .\qa\ci\reliability\check-crash-consistency.ps1 }
if (-not $SkipReleaseStatic) {
    Invoke-Step "Miri/sanitizer/fault-injection checks" { .\qa\ci\reliability\check-memory-safety.ps1 }
    Invoke-Step "WASM/browser lifecycle checks" { .\qa\ci\reliability\check-browser-lifecycle.ps1 }
} else {
    Write-Host "Miri/sanitizer and browser lifecycle gates deferred to check-all release sections." -ForegroundColor Yellow
}
Invoke-Step "metadata-leakage checks" { .\qa\ci\security\check-metadata-leakage.ps1 }
Invoke-Step "stego API shape checks" { python3 .\qa\ci\security\check-stego-api-shape.py }
Invoke-Step "persistence API shape checks" { .\qa\ci\security\check-persistence-api-shape.ps1 }
Invoke-Step "persistence invariant checks" { .\qa\ci\security\check-persistence-invariants.ps1 }
Invoke-Step "cross-runtime interop harness checks" { .\qa\ci\reliability\check-interop.ps1 }
Invoke-Step "independent handshake vector oracle" { python3 .\qa\independent\verify_handshake_vectors.py }
if (-not $SkipReleaseStatic) {
    Invoke-Step "critical-path coverage target checks" { .\qa\ci\quality\check-coverage.ps1 }
    Invoke-Step "mutation target checks" { .\qa\ci\quality\check-mutation.ps1 }
} else {
    Write-Host "Coverage and mutation gates deferred to check-all release sections." -ForegroundColor Yellow
}
Invoke-Step "cross-version compatibility checks" { .\qa\ci\reliability\check-cross-version-compat.ps1 }
Invoke-Step "mobile perf web persistence checks" { .\qa\ci\reliability\check-mobile-perf-web.ps1 }
Invoke-DocsGate
Invoke-Step "release-governance checks" { .\qa\ci\release\check-release-governance.ps1 }
Restore-CommittedLockForPolicy
Invoke-LockGate

if (!$SkipVectors) {
    Invoke-Step "qa vector checks" {
        cargo fmt --manifest-path qa/tools/vector-gen/Cargo.toml -- --check
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo test --release --locked --offline --manifest-path qa/tools/vector-gen/Cargo.toml
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo clippy --release --locked --offline --manifest-path qa/tools/vector-gen/Cargo.toml --all-targets -- -D warnings
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo run --release --locked --offline --manifest-path qa/tools/vector-gen/Cargo.toml -- --verify
    }
}

Write-Host ""
Write-Host "HYDRA-MSG tests-only validation passed." -ForegroundColor Green
