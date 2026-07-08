$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\..\..\.."
Set-Location $RepoRoot

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Host "wasm-pack is required. Install it with:" -ForegroundColor Yellow
    Write-Host "cargo install wasm-pack --locked" -ForegroundColor Yellow
    exit 1
}

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
Write-Host "Built mobile benchmark example-local WASM package: examples/mobile_perf_web/web/pkg" -ForegroundColor Green
