# HYDRA-MSG full release validation runner.
# By default this runs every validation section in order and stops at the first
# failing section. Use -From, -Through, -Only, or -ResumeFrom to run a subset.

[CmdletBinding()]
param(
    [ValidateSet("permissions", "tests", "examples", "miri", "sanitizers", "browser", "coverage", "mutation", "fuzz")]
    [string]$From = "permissions",
    [ValidateSet("permissions", "tests", "examples", "miri", "sanitizers", "browser", "coverage", "mutation", "fuzz")]
    [string]$ResumeFrom,
    [ValidateSet("permissions", "tests", "examples", "miri", "sanitizers", "browser", "coverage", "mutation", "fuzz")]
    [string]$Through = "fuzz",
    [ValidateSet("permissions", "tests", "examples", "miri", "sanitizers", "browser", "coverage", "mutation", "fuzz")]
    [string]$Only,
    [switch]$SkipPermissions,
    [switch]$SkipTests,
    [switch]$SkipExamples,
    [switch]$SkipMiri,
    [switch]$SkipSanitizers,
    [switch]$SkipBrowser,
    [switch]$SkipCoverage,
    [switch]$SkipMutation,
    [switch]$SkipFuzz,
    [switch]$CheckFormatOnly,
    [switch]$SkipVectors,
    [switch]$SkipWasm,
    [switch]$SkipBrowserInstall,
    [switch]$SkipMutationBaseline,
    [int]$MutationTimeout = 1200,
    [double]$MutationTimeoutMultiplier = 2,
    [int]$MutationMinimumTimeout = 120,
    [int]$MutationJobs = 1,
    [int]$FuzzRuns = 100000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

$Ranks = [ordered]@{
    permissions = 1
    tests = 2
    examples = 3
    miri = 4
    sanitizers = 5
    browser = 6
    coverage = 7
    mutation = 8
    fuzz = 9
}

if ($ResumeFrom) {
    $From = $ResumeFrom
}
if ($Only) {
    $From = $Only
    $Through = $Only
}
if ($Ranks[$From] -gt $Ranks[$Through]) {
    throw "-From $From occurs after -Through $Through"
}

function Test-ShouldRun {
    param(
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][bool]$Skip
    )
    return (-not $Skip) -and ($Ranks[$Section] -ge $Ranks[$From]) -and ($Ranks[$Section] -le $Ranks[$Through])
}

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

function Assert-PositiveInteger {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][int]$Value)
    if ($Value -le 0) { throw "$Name must be a positive integer, got: $Value" }
}

function Assert-PositiveNumber {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][double]$Value)
    if ($Value -le 0) { throw "$Name must be a positive number, got: $Value" }
}

$RanAny = $false
$ReleaseHeaderPrinted = $false
function Write-ReleaseHeader {
    if (-not $script:ReleaseHeaderPrinted) {
        Write-Host ""
        Write-Host "==> release evidence gates" -ForegroundColor Cyan
        Write-Host "Supply-chain evidence is included by core/check-tests.ps1 when the tests section is selected."
        $script:ReleaseHeaderPrinted = $true
    }
}

if (Test-ShouldRun "permissions" $SkipPermissions.IsPresent) {
    $RanAny = $true
    if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
        Write-Host ""
        Write-Host "==> Linux executable permissions" -ForegroundColor Cyan
        Write-Host "Skipping Unix execute-bit repair on Windows."
    } else {
        Invoke-Step "Linux executable permissions" { sh qa/ci/core/linux-permissions.sh }
    }
}

if (Test-ShouldRun "tests" $SkipTests.IsPresent) {
    $RanAny = $true
    $testArgs = @("-SkipReleaseStatic")
    if ($CheckFormatOnly) { $testArgs += "-CheckFormatOnly" }
    if ($SkipVectors) { $testArgs += "-SkipVectors" }
    Invoke-Step "tests/static validation" { .\qa\ci\core\check-tests.ps1 @testArgs }
}

if (Test-ShouldRun "examples" $SkipExamples.IsPresent) {
    $RanAny = $true
    $exampleArgs = @()
    if ($SkipWasm) { $exampleArgs += "-SkipWasm" }
    Invoke-Step "example validation" { .\qa\ci\core\check-examples.ps1 @exampleArgs }
}

if (Test-ShouldRun "miri" $SkipMiri.IsPresent) {
    $RanAny = $true
    Write-ReleaseHeader
    Invoke-EnvStep "Miri release evidence" @{ HYDRA_RUN_MIRI = "1" } {
        .\qa\ci\reliability\check-memory-safety.ps1
    }
}

if (Test-ShouldRun "sanitizers" $SkipSanitizers.IsPresent) {
    $RanAny = $true
    Write-ReleaseHeader
    Invoke-EnvStep "sanitizer release evidence" @{ HYDRA_RUN_SANITIZERS = "1" } {
        .\qa\ci\reliability\check-memory-safety.ps1
    }
}

if (Test-ShouldRun "browser" $SkipBrowser.IsPresent) {
    $RanAny = $true
    Write-ReleaseHeader
    $browserEnv = @{ HYDRA_RUN_BROWSER_E2E = "1" }
    if ($SkipBrowserInstall) { $browserEnv.HYDRA_SKIP_PLAYWRIGHT_INSTALL = "1" }
    Invoke-EnvStep "real browser Playwright lifecycle evidence" $browserEnv {
        .\qa\ci\reliability\check-browser-e2e.ps1
    }
}

if (Test-ShouldRun "coverage" $SkipCoverage.IsPresent) {
    $RanAny = $true
    Write-ReleaseHeader
    Invoke-EnvStep "coverage report release evidence" @{ HYDRA_RUN_COVERAGE = "1" } {
        .\qa\ci\quality\check-coverage.ps1
    }
}

if (Test-ShouldRun "mutation" $SkipMutation.IsPresent) {
    Assert-PositiveInteger "MutationTimeout" $MutationTimeout
    Assert-PositiveNumber "MutationTimeoutMultiplier" $MutationTimeoutMultiplier
    Assert-PositiveInteger "MutationMinimumTimeout" $MutationMinimumTimeout
    Assert-PositiveInteger "MutationJobs" $MutationJobs
    $RanAny = $true
    Write-ReleaseHeader
    if ($SkipMutationBaseline) {
        Invoke-EnvStep "mutation testing release evidence" @{
            HYDRA_RUN_MUTATION = "1"
            HYDRA_MUTATION_BASELINE = "skip"
            HYDRA_MUTATION_TIMEOUT = "$MutationTimeout"
            HYDRA_MUTATION_JOBS = "$MutationJobs"
        } {
            .\qa\ci\quality\check-mutation.ps1
        }
    } else {
        Invoke-EnvStep "mutation testing release evidence" @{
            HYDRA_RUN_MUTATION = "1"
            HYDRA_MUTATION_BASELINE = "run"
            HYDRA_MUTATION_TIMEOUT_MULTIPLIER = "$MutationTimeoutMultiplier"
            HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT = "$MutationMinimumTimeout"
            HYDRA_MUTATION_JOBS = "$MutationJobs"
        } {
            .\qa\ci\quality\check-mutation.ps1
        }
    }
}

if (Test-ShouldRun "fuzz" $SkipFuzz.IsPresent) {
    Assert-PositiveInteger "FuzzRuns" $FuzzRuns
    $RanAny = $true
    Write-ReleaseHeader
    Invoke-EnvStep "overnight coverage-guided fuzz evidence" @{
        HYDRA_RUN_COVERAGE_GUIDED_FUZZ = "1"
        HYDRA_COVERAGE_FUZZ_RUNS = "$FuzzRuns"
    } {
        .\qa\ci\fuzz\check-fuzz.ps1
    }
}

Write-Host ""
if ($RanAny) {
    Write-Host "HYDRA-MSG selected release validation sections passed." -ForegroundColor Green
} else {
    Write-Host "No validation sections were selected." -ForegroundColor Yellow
}
