# HYDRA-MSG cross-version compatibility gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

cargo test -p hydra-cross-version-compat
if ($LASTEXITCODE -ne 0) {
    throw "cross-version compatibility checks failed with exit code $LASTEXITCODE"
}

Write-Host "cross-version compatibility checks passed." -ForegroundColor Green
