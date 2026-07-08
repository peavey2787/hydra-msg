$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\..\..\.."
Set-Location $RepoRoot

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Host "wasm-pack is required for this example. Install with:" -ForegroundColor Yellow
    Write-Host "cargo install wasm-pack --locked" -ForegroundColor Yellow
    exit 1
}

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/webrtc_manual_carrier/web/pkg
Write-Host "Built WebRTC manual carrier WASM package." -ForegroundColor Green
