# HYDRA-MSG full validation runner.
# Runs the non-interactive checks for the active workspace.
# Example runs live in qa\ci\check-examples.ps1 so normal tests do not wait on browser/example flows.

[CmdletBinding()]
param(
    [switch]$CheckFormatOnly,
    [switch]$SkipVectors
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

function Assert-NoTextMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$Roots,
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    $files = foreach ($root in $Roots) {
        if (Test-Path $root) {
            Get-ChildItem $root -Recurse -File |
                Where-Object {
                    $_.FullName -notmatch '\\target\\' -and
                    $_.FullName -notmatch '\\.git\\' -and
                    $_.FullName -notmatch '\\qa\\vectors\\candidate\\' -and
                    $_.Extension -notin @('.bin', '.png', '.jpg', '.jpeg', '.gif', '.zip')
                }
        }
    }

    $matches = $files | Select-String -Pattern $Pattern -CaseSensitive:$false
    if ($matches) {
        $matches | ForEach-Object { Write-Host $_ }
        throw "$Name found forbidden text"
    }
}

function Assert-PathExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (!(Test-Path $Path)) {
        throw "Required path missing: $Path"
    }
}

function Invoke-DocsGate {
    Write-Host ""
    Write-Host "==> docs/path/stale-term checks" -ForegroundColor Cyan

    foreach ($path in @(
        "docs/spec",
        "docs/impl",
        "docs/validation",
        "docs/project",
        "qa/ci",
        "qa/tools/vector-gen",
        "qa/vectors/candidate"
    )) {
        Assert-PathExists $path
    }

    Assert-NoTextMatch "stale docs/planning references" @("docs", "crates", "README.md", "Cargo.toml") "docs/planning"
    Assert-NoTextMatch "crate name references" @("docs", "crates", "README.md", "Cargo.toml") "hydra-types|hydra-wire"
    Assert-NoTextMatch "primitive terminology" @("docs/spec", "docs/impl", "docs/validation", "crates") "Kyber|Dilithium|XChaCha20"
    Assert-NoTextMatch "source TODO/unimplemented markers" @("crates") "todo!|unimplemented!|TODO|FIXME"

    $emptyScripts = Get-ChildItem "qa/ci" -File |
        Where-Object { $_.Extension -in @('.sh', '.ps1') -and $_.Length -eq 0 }
    if ($emptyScripts) {
        $emptyScripts | ForEach-Object { Write-Host $_.FullName }
        throw "empty QA script found"
    }

    Write-Host "docs/path/stale-term checks passed." -ForegroundColor Green
}

if ($CheckFormatOnly) {
    Invoke-Step "cargo fmt --check" { cargo fmt --all -- --check }
} else {
    Invoke-Step "cargo fmt" { cargo fmt --all }
}
Invoke-Step "cargo test --workspace" { cargo test --workspace }
Invoke-Step "cargo clippy --workspace --all-targets -- -D warnings" {
    cargo clippy --workspace --all-targets -- -D warnings
}
Invoke-DocsGate

if (!$SkipVectors) {
    Invoke-Step "qa vector checks" {
        if ($CheckFormatOnly) {
            cargo fmt --manifest-path qa/tools/vector-gen/Cargo.toml -- --check
        } else {
            cargo fmt --manifest-path qa/tools/vector-gen/Cargo.toml
        }
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo test --release --locked --offline --manifest-path qa/tools/vector-gen/Cargo.toml
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo clippy --release --locked --offline --manifest-path qa/tools/vector-gen/Cargo.toml --all-targets -- -D warnings
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        cargo run --release --locked --offline --manifest-path qa/tools/vector-gen/Cargo.toml -- --verify
    }
}

Write-Host ""
Write-Host "HYDRA-MSG full validation passed." -ForegroundColor Green
Write-Host "Run qa\ci\check-examples.ps1 separately for runnable examples and browser package checks."
