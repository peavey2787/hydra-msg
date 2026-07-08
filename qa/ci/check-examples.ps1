[CmdletBinding()]
param(
    [switch]$SkipWasm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

Invoke-Step "handshake_roundtrip example" {
    cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
}
Invoke-Step "contact_card example" {
    cargo run --manifest-path examples/contact_card/Cargo.toml
}
Invoke-Step "attachment_roundtrip example" {
    cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
}
Invoke-Step "lobby_roundtrip example" {
    cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
}
Invoke-Step "manual_file_carrier example" {
    cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
}

Invoke-Step "mobile_perf_web host compile" {
    cargo check --manifest-path examples/mobile_perf_web/Cargo.toml
}
Invoke-Step "webrtc_manual_carrier host compile" {
    cargo check --manifest-path examples/webrtc_manual_carrier/Cargo.toml
}

if (!$SkipWasm) {
    if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
        Write-Host "wasm-pack is required for browser example packages." -ForegroundColor Red
        Write-Host "Install with: cargo install wasm-pack --locked" -ForegroundColor Yellow
        exit 1
    }

    Invoke-Step "mobile_perf_web WASM package" {
        examples\mobile_perf_web\scripts\build-wasm.ps1
    }
    Invoke-Step "webrtc_manual_carrier WASM package" {
        examples\webrtc_manual_carrier\scripts\build-wasm.ps1
    }
} else {
    Write-Host "WASM browser package checks skipped by -SkipWasm." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "HYDRA-MSG example checks passed." -ForegroundColor Green
