$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot
Write-Host "HYDRA-MSG repo root: $RepoRoot"

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Host "wasm-pack is required to build the reusable web package." -ForegroundColor Red
    Write-Host "Install with: cargo install wasm-pack --locked" -ForegroundColor Yellow
    exit 1
}

$OutputDir = Join-Path $RepoRoot "target\hydra-msg-wasm\web"
if (Test-Path $OutputDir) {
    Remove-Item -Recurse -Force $OutputDir
}

wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../target/hydra-msg-wasm/web
if ($LASTEXITCODE -ne 0) {
    throw "wasm-pack failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Built reusable HYDRA-MSG WASM web package:" -ForegroundColor Green
Write-Host "  $OutputDir"
Write-Host ""
Write-Host "Use example-specific scripts only when you want example-local web/pkg output."
