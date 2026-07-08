# HYDRA-MSG tests-only validation runner.
# Runs workspace tests plus non-example static validation gates.
# Runnable examples and browser package checks live in qa\ci\check-examples.ps1.

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

function Get-LockPairs {
    param([Parameter(Mandatory = $true)][string]$Path)

    $pairs = New-Object System.Collections.Generic.List[string]
    $name = $null
    $version = $null
    foreach ($line in Get-Content $Path) {
        if ($line -eq "[[package]]") {
            if ($name -and $version) {
                $pairs.Add("$name $version")
            }
            $name = $null
            $version = $null
            continue
        }
        if ($line -match '^name = "(.+)"$') {
            $name = $Matches[1]
            continue
        }
        if ($line -match '^version = "(.+)"$') {
            $version = $Matches[1]
            continue
        }
    }
    if ($name -and $version) {
        $pairs.Add("$name $version")
    }
    $pairs | Sort-Object -Unique
}

function Invoke-LockGate {
    Write-Host ""
    Write-Host "==> lock-file checks" -ForegroundColor Cyan
    $rootPairs = @(Get-LockPairs "Cargo.lock")
    $rootSet = @{}
    foreach ($pair in $rootPairs) {
        $rootSet[$pair] = $true
    }

    $missing = @()
    foreach ($pair in @(Get-LockPairs "qa/tools/vector-gen/Cargo.lock")) {
        if ($pair -eq "hydra-vector-gen 0.1.0") {
            continue
        }
        if (!$rootSet.ContainsKey($pair)) {
            $missing += $pair
        }
    }

    if ($missing.Count -gt 0) {
        $missing | ForEach-Object { Write-Host "  $_" }
        throw "vector tool lock contains package versions not present in the main workspace lock"
    }
    Write-Host "lock-file checks passed." -ForegroundColor Green
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

    $unexpectedTopLevelDocs = Get-ChildItem "docs" -File | Where-Object { $_.Name -ne "roadmap.md" }
    if ($unexpectedTopLevelDocs) {
        $unexpectedTopLevelDocs | ForEach-Object { Write-Host $_.FullName }
        throw "unexpected top-level docs file found"
    }

    $projectFiles = Get-ChildItem "docs/project" -File -Recurse | Where-Object {
        $_.FullName -notmatch "[\\/]docs[\\/]project[\\/]audit[\\/]"
    }
    if ($projectFiles) {
        $projectFiles | ForEach-Object { Write-Host $_.FullName }
        throw "non-audit file found under docs/project"
    }

    $readmes = Get-ChildItem . -Filter README.md -File -Recurse |
        Where-Object { $_.FullName -notmatch "[\\/]\.git[\\/]" -and $_.FullName -notmatch "[\\/]target[\\/]" }
    foreach ($readme in $readmes) {
        if ($readme.FullName -eq (Join-Path $RepoRoot "README.md")) {
            continue
        }
        if ((Get-Content $readme.FullName -Raw) -notmatch "Main README") {
            throw "README missing Main README navigation: $($readme.FullName)"
        }
    }

    $importantDocs = Get-ChildItem @("docs/spec", "docs/impl", "docs/validation") -Filter *.md -File -Recurse
    foreach ($doc in $importantDocs) {
        $content = Get-Content $doc.FullName -Raw
        if ($content -notmatch "(?m)^## Navigation$") {
            throw "Markdown doc missing Navigation section: $($doc.FullName)"
        }
        if ($content -notmatch "Main README") {
            throw "Markdown doc missing Main README navigation: $($doc.FullName)"
        }
        $specReadme = Join-Path $RepoRoot "docs/spec/README.md"
        if ($doc.FullName -ne $specReadme -and $content -notmatch "Spec docs") {
            throw "Markdown doc missing Spec docs navigation: $($doc.FullName)"
        }
    }

    Assert-NoTextMatch "docs/planning references" @("docs", "crates", "README.md", "Cargo.toml") "docs/planning"
    Assert-NoTextMatch "product doc references under docs/project" @("docs", "crates", "examples", "README.md", "Cargo.toml") "docs/project/(message-flow|public-developer-api|benchmark-results|carrier-examples|hydra-msg-cli|wasm-javascript-bindings|production-qa-gate|release-readiness)"
    Assert-NoTextMatch "crate name references" @("docs", "crates", "README.md", "Cargo.toml") "hydra-types|hydra-wire"
    Assert-NoTextMatch "primitive terminology" @("docs/spec", "docs/impl", "docs/validation", "crates") "Kyber|Dilithium|XChaCha20"
    Assert-NoTextMatch "source TODO/unimplemented markers" @("crates") "todo!|unimplemented!|TODO|FIXME"

    $emptyScripts = Get-ChildItem "qa/ci" -File |
        Where-Object { $_.Extension -in @('.sh', '.ps1') -and $_.Length -eq 0 }
    if ($emptyScripts) {
        $emptyScripts | ForEach-Object { Write-Host $_.FullName }
        throw "empty QA script found"
    }

    Invoke-Step "Markdown link checks" { .\qa\ci\check-markdown-links.ps1 }

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
Invoke-Step "rust file size ownership checks" { .\qa\ci\check-rust-file-sizes.ps1 }
Invoke-DocsGate
Invoke-LockGate

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
Write-Host "HYDRA-MSG tests-only validation passed." -ForegroundColor Green
