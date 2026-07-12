# HYDRA-MSG tests-only validation runner.
# Runs workspace tests plus non-example static validation gates.
# Runnable examples and browser package checks live in qa\ci\core\check-examples.ps1.

[CmdletBinding()]
param(
    [switch]$CheckFormatOnly,
    [switch]$SkipVectors,
    [switch]$SkipReleaseStatic
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
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

function Get-NavigationBlock {
    param([Parameter(Mandatory = $true)][string]$Path)

    $lines = Get-Content $Path
    $inNav = $false
    $navLines = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -eq "## Navigation") {
            $inNav = $true
            $navLines.Add($line)
            continue
        }
        if ($inNav -and $line.StartsWith("## ")) {
            break
        }
        if ($inNav) {
            $navLines.Add($line)
        }
    }
    return ($navLines -join "`n")
}

function Assert-NavLabel {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Nav,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (!$Nav.Contains("[$Label]")) {
        throw "navigation missing $Label: $File"
    }
}

function Assert-NoNavLabel {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Nav,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Nav.Contains("[$Label]")) {
        throw "navigation has wrong nav-family entry $Label: $File"
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
    python3 .\qa\ci\policy\check-workspace-lock.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

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
        "docs/validation/benchmarks",
        "qa/ci",
        "docs/validation/evidence",
        "docs/validation/gates",
        "docs/validation/release",
        "qa/fixtures/interop",
        "qa/tests",
        "qa/tools/vector-gen",
        "qa/vectors/candidate",
        "qa/vectors/cross-version"
    )) {
        Assert-PathExists $path
    }

    $unexpectedTopLevelDocs = Get-ChildItem "docs" -File
    if ($unexpectedTopLevelDocs) {
        $unexpectedTopLevelDocs | ForEach-Object { Write-Host $_.FullName }
        throw "unexpected top-level docs file found"
    }

    if (Test-Path "docs/project") {
        $projectFiles = Get-ChildItem "docs/project" -File -Recurse
        if ($projectFiles) {
            $projectFiles | ForEach-Object { Write-Host $_.FullName }
            throw "persistent file found under docs/project; move release evidence to docs/validation/evidence"
        }
    }

    if (Test-Path "qa/evidence") {
        throw "qa/evidence must not exist; move long-lived documentation to docs/validation/evidence"
    }

    $mainNav = Get-NavigationBlock "README.md"
    foreach ($label in @(
        "How HYDRA messaging works",
        "Spec docs and repo structure",
        "Crates",
        "Examples",
        "Public developer API",
        "Benchmark notes"
    )) {
        Assert-NavLabel "README.md" $mainNav $label
    }
    foreach ($label in @(
        "Roadmap",
        "Protocol spec",
        "Threat model",
        "Security proof sketch",
        "State machines",
        "Envelope serialization",
        "Chain-key evolution",
        "TreeKEM profile",
        "Group modes",
        "Group rekey",
        "Anonymous authorization"
    )) {
        Assert-NoNavLabel "README.md" $mainNav $label
    }

    $readmes = Get-ChildItem . -Filter README.md -File -Recurse |
        Where-Object { $_.FullName -notmatch "[\/]\.git[\/]" -and $_.FullName -notmatch "[\/]target[\/]" -and $_.FullName -notmatch "[\/]node_modules[\/]" -and $_.FullName -notmatch "[\/]test-results[\/]" -and $_.FullName -notmatch "[\/]playwright-report[\/]" -and $_.FullName -notmatch "(^|[\/])examples[\/][^\/]+[\/]web[\/]pkg[\/]" }
    foreach ($readme in $readmes) {
        if ($readme.FullName -eq (Join-Path $RepoRoot "README.md")) {
            continue
        }
        if ((Get-Content $readme.FullName -Raw) -notmatch "Main README") {
            throw "README missing Main README navigation: $($readme.FullName)"
        }
    }

    function Test-MainNavDoc {
        param([Parameter(Mandatory = $true)][string]$Path)
        $normalized = $Path.Replace('\', '/')
        return (
            $normalized.StartsWith("crates/") -or
            $normalized.StartsWith("examples/") -or
            $normalized -eq "docs/impl/message-flow/README.md" -or
            $normalized -eq "docs/impl/carrier-examples.md" -or
            $normalized -eq "docs/impl/hydra-msg-cli.md" -or
            $normalized -eq "docs/impl/wasm-javascript-bindings.md" -or
            $normalized -eq "docs/spec/public-developer-api.md" -or
            $normalized -eq "docs/validation/benchmarks/benchmark-results.md"
        )
    }

    function Test-ValidationNavDoc {
        param([Parameter(Mandatory = $true)][string]$Path)
        return $Path.Replace('\', '/').StartsWith("docs/validation/")
    }

    function Assert-MainNavFamily {
        param(
            [Parameter(Mandatory = $true)][string]$File,
            [Parameter(Mandatory = $true)][string]$Nav
        )
        foreach ($label in @(
            "Main README",
            "How HYDRA messaging works",
            "Spec docs and repo structure",
            "Crates",
            "Examples",
            "Public developer API",
            "Benchmark notes"
        )) {
            Assert-NavLabel $File $Nav $label
        }
        foreach ($label in @(
            "Roadmap",
            "Spec document index",
            "Protocol spec",
            "Threat model",
            "Security proof sketch",
            "State machines",
            "Envelope serialization",
            "Chain-key evolution",
            "TreeKEM profile",
            "Group modes",
            "Group rekey",
            "Anonymous authorization"
        )) {
            Assert-NoNavLabel $File $Nav $label
        }
    }

    function Assert-SpecNavFamily {
        param(
            [Parameter(Mandatory = $true)][string]$File,
            [Parameter(Mandatory = $true)][string]$Nav
        )
        foreach ($label in @(
            "Main README",
            "Spec document index",
            "Protocol spec",
            "Threat model",
            "Security proof sketch",
            "State machines",
            "Envelope serialization",
            "Chain-key evolution",
            "TreeKEM profile",
            "Group modes",
            "Group rekey",
            "Anonymous authorization"
        )) {
            Assert-NavLabel $File $Nav $label
        }
        foreach ($label in @(
            "How HYDRA messaging works",
            "Spec docs and repo structure",
            "Crates",
            "Examples",
            "Public developer API",
            "Benchmark notes",
            "Carrier examples",
            "Production QA gate",
            "Roadmap"
        )) {
            Assert-NoNavLabel $File $Nav $label
        }
    }

    function Assert-ValidationNavFamily {
        param(
            [Parameter(Mandatory = $true)][string]$File,
            [Parameter(Mandatory = $true)][string]$Nav
        )
        foreach ($label in @(
            "Main README",
            "Validation index",
            "Spec document index",
            "Threat model"
        )) {
            Assert-NavLabel $File $Nav $label
        }
        foreach ($label in @(
            "How HYDRA messaging works",
            "Spec docs and repo structure",
            "Crates",
            "Examples",
            "Public developer API",
            "Benchmark notes",
            "Roadmap"
        )) {
            Assert-NoNavLabel $File $Nav $label
        }
    }

    $importantDocs = @()
    foreach ($root in @("crates", "examples", "docs/spec", "docs/impl", "docs/validation")) {
        $importantDocs += Get-ChildItem $root -Filter *.md -File -Recurse |
            Where-Object { $_.FullName -notmatch "[\/]node_modules[\/]" -and $_.FullName -notmatch "[\/]test-results[\/]" -and $_.FullName -notmatch "[\/]playwright-report[\/]" -and $_.FullName -notmatch "(^|[\/])examples[\/][^\/]+[\/]web[\/]pkg[\/]" }
    }
    foreach ($doc in $importantDocs) {
        $content = Get-Content $doc.FullName -Raw
        if ($content -notmatch "(?m)^## Navigation$") {
            throw "Markdown doc missing Navigation section: $($doc.FullName)"
        }

        $relative = Resolve-Path -Relative $doc.FullName
        $relative = ($relative -replace '^[.][\\/]', '').Replace('\', '/')
        $docNav = Get-NavigationBlock $doc.FullName
        if (Test-MainNavDoc $relative) {
            Assert-MainNavFamily $doc.FullName $docNav
        } elseif (Test-ValidationNavDoc $relative) {
            Assert-ValidationNavFamily $doc.FullName $docNav
        } else {
            Assert-SpecNavFamily $doc.FullName $docNav
        }
    }

    Assert-NoTextMatch "blocked simple-API wording" @("README.md", "crates", "examples", "docs", "Cargo.toml") "stupid[-]simple|stupid[ ]simple"
    Assert-NoTextMatch "docs/planning references" @("docs", "crates", "README.md", "Cargo.toml") "docs/planning"
    Assert-NoTextMatch "long-lived docs/project references" @("docs", "crates", "examples", "README.md", "Cargo.toml") "docs/project/"
    Assert-NoTextMatch "crate name references" @("docs", "crates", "README.md", "Cargo.toml") "hydra-types|hydra-wire"
    Assert-NoTextMatch "primitive terminology" @("docs/spec", "docs/impl", "docs/validation", "crates") "Kyber|Dilithium|XChaCha20"
    Assert-NoTextMatch "source TODO/unimplemented markers" @("crates") "todo!|unimplemented!|TODO|FIXME"

    $emptyScripts = Get-ChildItem "qa/ci" -File -Recurse |
        Where-Object { $_.Extension -in @('.sh', '.ps1') -and $_.Length -eq 0 }
    if ($emptyScripts) {
        $emptyScripts | ForEach-Object { Write-Host $_.FullName }
        throw "empty QA script found"
    }

    Invoke-Step "Markdown link checks" { .\qa\ci\policy\check-markdown-links.ps1 }

    Write-Host "docs/path/stale-term checks passed." -ForegroundColor Green
}

Invoke-Step "cargo metadata --locked" { cargo metadata --locked --format-version 1 --no-deps | Out-Null }

if ($CheckFormatOnly) {
    Invoke-Step "cargo fmt --check" { cargo fmt --all -- --check }
} else {
    Invoke-Step "cargo fmt" { cargo fmt --all }
}
Invoke-Step "cargo test --workspace --all-targets" { cargo test --workspace --all-targets }
Invoke-Step "cargo clippy --workspace --all-targets -- -D warnings" {
    cargo clippy --workspace --all-targets -- -D warnings
}
Invoke-Step "supply-chain advisory/license checks" { .\qa\ci\security\check-supply-chain.ps1 }
Invoke-Step "rust file size ownership checks" { .\qa\ci\policy\check-rust-file-sizes.ps1 }
Invoke-Step "privacy invariant checks" { .\qa\ci\security\check-privacy-invariants.ps1 }
Invoke-Step "resource-exhaustion/DoS limit checks" { .\qa\ci\security\check-resource-limits.ps1 }
Invoke-Step "crash-consistency matrix checks" { .\qa\ci\reliability\check-crash-consistency.ps1 }
if (-not $SkipReleaseStatic) {
    Invoke-Step "Miri/sanitizer/fault-injection checks" { .\qa\ci\reliability\check-memory-safety.ps1 }
    Invoke-Step "WASM/browser lifecycle checks" { .\qa\ci\reliability\check-browser-lifecycle.ps1 }
} else {
    Write-Host "Miri/sanitizer and browser lifecycle gates deferred to check-all release sections." -ForegroundColor Yellow
}
Invoke-Step "metadata-leakage checks" { .\qa\ci\security\check-metadata-leakage.ps1 }
Invoke-Step "persistence API shape checks" { .\qa\ci\security\check-persistence-api-shape.ps1 }
Invoke-Step "persistence invariant checks" { .\qa\ci\security\check-persistence-invariants.ps1 }
Invoke-Step "cross-runtime interop harness checks" { .\qa\ci\reliability\check-interop.ps1 }
if (-not $SkipReleaseStatic) {
    Invoke-Step "critical-path coverage target checks" { .\qa\ci\quality\check-coverage.ps1 }
    Invoke-Step "mutation target checks" { .\qa\ci\quality\check-mutation.ps1 }
} else {
    Write-Host "Coverage and mutation gates deferred to check-all release sections." -ForegroundColor Yellow
}
Invoke-Step "cross-version compatibility checks" { .\qa\ci\reliability\check-cross-version-compat.ps1 }
Invoke-Step "mobile perf web persistence checks" { .\qa\ci\reliability\check-mobile-perf-web.ps1 }
Invoke-DocsGate
Invoke-Step "release-governance checks" { .\qa\ci\release\check-release-governance.ps1 }
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
