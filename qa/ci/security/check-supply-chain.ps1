# HYDRA-MSG dependency supply-chain gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-Command {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InstallCrate
    )
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "missing required tool: $Name; install with: cargo install $InstallCrate --locked, or run .\scripts\setup-dev-env.ps1"
    }
}

Assert-Command "cargo-audit" "cargo-audit"
Assert-Command "cargo-deny" "cargo-deny"

if (-not (Test-Path "deny.toml")) {
    throw "missing deny.toml"
}
if (-not (Test-Path "LICENSE")) {
    throw "missing LICENSE"
}

$licenseMatches = Get-ChildItem Cargo.toml, crates, examples, qa -Recurse -Filter Cargo.toml |
    Select-String -Pattern 'license = "MIT OR Apache-2.0"'
if ($licenseMatches) {
    $licenseMatches | ForEach-Object { Write-Host $_ }
    throw "stale pre-freeze MIT OR Apache license string found in Cargo.toml files"
}

if (-not ((Get-Content "Cargo.toml" -Raw).Contains('license = "GPL-2.0-or-later"'))) {
    throw "workspace license must be GPL-2.0-or-later"
}

Write-Host ""
Write-Host "==> refresh root Cargo.lock" -ForegroundColor Cyan
Remove-Item -LiteralPath "Cargo.lock" -Force -ErrorAction SilentlyContinue
cargo generate-lockfile
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo fetch
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "==> cargo-audit advisories" -ForegroundColor Cyan
cargo audit --deny warnings
if ($LASTEXITCODE -ne 0) {
    throw "cargo-audit failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "==> cargo-deny advisories/bans/licenses/sources" -ForegroundColor Cyan
cargo deny check advisories bans licenses sources
if ($LASTEXITCODE -ne 0) {
    throw "cargo-deny failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "HYDRA-MSG supply-chain checks passed." -ForegroundColor Green
