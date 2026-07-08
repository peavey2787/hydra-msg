$ErrorActionPreference = "Stop"

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Host "wasm-pack is required. Install it with: cargo install wasm-pack --locked" -ForegroundColor Red
    exit 1
}

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
