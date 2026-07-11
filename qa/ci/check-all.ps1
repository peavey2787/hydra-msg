# HYDRA-MSG full release validation runner.
# Fast mandatory validation runs first. Expensive release-evidence gates run
# near the bottom. The overnight coverage-guided fuzz campaign is last.

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

function Invoke-EnvStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [hashtable]$Environment,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    $oldValues = @{}
    foreach ($key in $Environment.Keys) {
        $oldValues[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
        [Environment]::SetEnvironmentVariable($key, [string]$Environment[$key], "Process")
    }

    try {
        Invoke-Step $Name $Command
    } finally {
        foreach ($key in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable($key, $oldValues[$key], "Process")
        }
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

Invoke-Step "tests/static validation" { .\qa\ci\core\check-tests.ps1 @testArgs }
Invoke-Step "example validation" { .\qa\ci\core\check-examples.ps1 @exampleArgs }

Write-Host ""
Write-Host "==> release evidence gates" -ForegroundColor Cyan
Write-Host "Supply-chain evidence is included above by core/check-tests.ps1 via qa/ci/security/check-supply-chain.ps1."

Invoke-EnvStep "Miri release evidence" @{ HYDRA_RUN_MIRI = "1" } {
    .\qa\ci\reliability\check-memory-safety.ps1
}

Invoke-EnvStep "sanitizer release evidence" @{ HYDRA_RUN_SANITIZERS = "1" } {
    .\qa\ci\reliability\check-memory-safety.ps1
}

Invoke-EnvStep "real browser Playwright lifecycle evidence" @{ HYDRA_RUN_BROWSER_E2E = "1" } {
    .\qa\ci\reliability\check-browser-e2e.ps1
}

Invoke-EnvStep "coverage report release evidence" @{ HYDRA_RUN_COVERAGE = "1" } {
    .\qa\ci\quality\check-coverage.ps1
}

Invoke-EnvStep "mutation testing release evidence" @{ HYDRA_RUN_MUTATION = "1" } {
    .\qa\ci\quality\check-mutation.ps1
}

$fuzzRuns = if ($env:HYDRA_COVERAGE_FUZZ_RUNS) { $env:HYDRA_COVERAGE_FUZZ_RUNS } else { "100000" }
Invoke-EnvStep "overnight coverage-guided fuzz evidence" @{
    HYDRA_RUN_COVERAGE_GUIDED_FUZZ = "1"
    HYDRA_COVERAGE_FUZZ_RUNS = $fuzzRuns
} {
    .\qa\ci\fuzz\check-fuzz.ps1
}

Write-Host ""
Write-Host "HYDRA-MSG full release validation passed." -ForegroundColor Green
