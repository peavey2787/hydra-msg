# HYDRA-MSG memory-safety and fault-injection gate.
# Mandatory: targeted fault-injection crash-consistency tests.
# Optional: nightly Miri and sanitizer runs when HYDRA_RUN_MIRI/HYDRA_RUN_SANITIZERS are set.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required memory-safety gate file missing: $Path"
    }
}

function Assert-TextPresent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (!(Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet)) {
        throw "Memory-safety invariant missing from ${Path}: $Text"
    }
}

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Command)
    if (!(Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "Required command missing: $Command"
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

$policy = "docs/validation/gates/miri-sanitizer-fault-injection.md"
$crashTests = "crates/hydra-msg/src/tests/crash_consistency.rs"
$nativeStore = "crates/hydra-msg/src/persistence/native_store.rs"

foreach ($path in @($policy, $crashTests, $nativeStore)) {
    Assert-FileExists $path
}

foreach ($text in @(
    "Miri",
    "sanitizer",
    "fault-injection",
    "HYDRA_RUN_MIRI=1",
    "HYDRA_RUN_SANITIZERS=1"
)) {
    Assert-TextPresent $policy $text
}

foreach ($stage in @(
    "write temp file",
    "sync temp file",
    "rename/replace state",
    "sync parent dir"
)) {
    Assert-TextPresent $nativeStore "test_failpoint(path, `"$stage`")?"
    Assert-TextPresent $crashTests $stage
}

Assert-TextPresent $nativeStore "#[cfg(test)]"
Assert-TextPresent $nativeStore "set_test_failpoint"
Assert-TextPresent $crashTests "backup_import_failure_is_atomic_in_memory_and_on_disk"
Assert-TextPresent $crashTests "delete_identity_failure_restores_memory_and_disk"
Assert-TextPresent $crashTests "delete_contact_failure_restores_memory_and_disk"
Assert-TextPresent $crashTests "delete_message_failure_restores_memory_and_disk"

Assert-Command cargo
Invoke-Step "fault-injection crash-consistency tests" {
    cargo test -p hydra-msg --lib tests::crash_consistency
}

if ($env:HYDRA_RUN_MIRI -eq "1") {
    Assert-Command rustup
    Assert-Command cargo
    cargo +nightly miri --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cargo +nightly miri is unavailable. Install nightly and Miri with rustup toolchain install nightly; rustup +nightly component add miri"
    }
    if (!$env:MIRIFLAGS) {
        $env:MIRIFLAGS = "-Zmiri-disable-isolation"
    }
    $packages = if ($env:HYDRA_MIRI_PACKAGES) { $env:HYDRA_MIRI_PACKAGES } else { "hydra-core hydra-envelope hydra-session" }
    foreach ($package in $packages.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)) {
        Invoke-Step "Miri: $package" { cargo +nightly miri test -p $package }
    }
} else {
    Write-Host ""
    Write-Host "Miri execution skipped. Set HYDRA_RUN_MIRI=1 for the nightly Miri gate."
}

if ($env:HYDRA_RUN_SANITIZERS -eq "1") {
    Assert-Command rustup
    Assert-Command cargo
    cargo +nightly -Z help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cargo +nightly is unavailable. Install nightly first with rustup toolchain install nightly"
    }
    $sanitizer = if ($env:HYDRA_SANITIZER) { $env:HYDRA_SANITIZER } else { "address" }
    $target = if ($env:HYDRA_SANITIZER_TARGET) { $env:HYDRA_SANITIZER_TARGET } else { "x86_64-unknown-linux-gnu" }
    $packages = if ($env:HYDRA_SANITIZER_PACKAGES) { $env:HYDRA_SANITIZER_PACKAGES } else { "hydra-core hydra-envelope hydra-session hydra-msg" }
    $env:RUSTFLAGS = "-Zsanitizer=$sanitizer $env:RUSTFLAGS"
    foreach ($package in $packages.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)) {
        Invoke-Step "sanitizer($sanitizer): $package" {
            cargo +nightly test -Zbuild-std --target $target -p $package
        }
    }
} else {
    Write-Host ""
    Write-Host "Sanitizer execution skipped. Set HYDRA_RUN_SANITIZERS=1 for the nightly sanitizer gate."
}

Write-Host ""
Write-Host "Miri/sanitizer/fault-injection gate passed." -ForegroundColor Green
