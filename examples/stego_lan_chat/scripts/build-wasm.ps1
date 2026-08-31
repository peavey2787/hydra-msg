$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\..\..\.."
Set-Location $RepoRoot

if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
    Write-Host "wasm-pack is required. Install it with cargo install wasm-pack --locked." -ForegroundColor Yellow
    exit 1
}

$HydraWasmStackSize = if ($env:HYDRA_WASM_STACK_SIZE) { $env:HYDRA_WASM_STACK_SIZE } else { "16777216" }
# A previous version leaked this WASM-only linker flag into the caller's
# PowerShell environment, which makes the native MinGW linker reject `-z`.
$HydraNativeRustFlags = (($env:RUSTFLAGS -replace '(?:^|\s)-C\s+link-arg=-zstack-size=\d+(?=\s|$)', '').Trim())
$env:RUSTFLAGS = (("$HydraNativeRustFlags -C link-arg=-zstack-size=$HydraWasmStackSize").Trim())

$OutDir = "examples/stego_lan_chat/web/pkg"
try {
    if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
    wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/stego_lan_chat/web/pkg
    if ($LASTEXITCODE -ne 0) {
        throw "wasm-pack failed with exit code $LASTEXITCODE"
    }
    @("*", "!.gitignore", "!.gitkeep") | Set-Content "$OutDir/.gitignore"
    New-Item -ItemType File -Force "$OutDir/.gitkeep" | Out-Null
} finally {
    if ($HydraNativeRustFlags) {
        $env:RUSTFLAGS = $HydraNativeRustFlags
    } else {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    }
}
Write-Host "Built the steganographic LAN chat WASM package." -ForegroundColor Green
