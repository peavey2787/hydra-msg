# HYDRA-MSG full validation runner.
# Thin top-level gate: tests/static validation first, then runnable examples/browser packages.

[CmdletBinding()]
param(
    [switch]$CheckFormatOnly,
    [switch]$SkipVectors,
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

$testArgs = @()
if ($CheckFormatOnly) {
    $testArgs += "-CheckFormatOnly"
}
if ($SkipVectors) {
    $testArgs += "-SkipVectors"
}

$exampleArgs = @()
if ($SkipWasm) {
    $exampleArgs += "-SkipWasm"
}

Invoke-Step "tests/static validation" { .\qa\ci\check-tests.ps1 @testArgs }
Invoke-Step "example validation" { .\qa\ci\check-examples.ps1 @exampleArgs }

Write-Host ""
Write-Host "HYDRA-MSG full validation passed." -ForegroundColor Green
