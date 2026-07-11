$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRootScript = Join-Path $scriptDir "..\lib\repo-root.sh"
if (Get-Command git -ErrorAction SilentlyContinue) {
    $repoRoot = (git rev-parse --show-toplevel).Trim()
    Set-Location $repoRoot
}

$requiredFiles = @(
    "CHANGELOG.md",
    "SECURITY.md",
    "docs/validation/release/release-checklist.md",
    "docs/validation/release/release-artifacts.md",
    "docs/validation/release/release-signing.md",
    "docs/validation/release/sbom.md",
    "docs/validation/release/reproducible-builds.md",
    "docs/validation/release/supported-platforms.md",
    "docs/validation/release/msrv-policy.md",
    "docs/validation/release/dependency-update-policy.md",
    "docs/validation/release/security-advisory-policy.md",
    "docs/validation/release/responsible-disclosure.md",
    "docs/validation/release/external-review-status.md",
    "scripts/release/generate-sbom.py",
    "scripts/release/create-release-package.ps1",
    "scripts/release/sign-release-artifacts.ps1",
    "scripts/release/verify-release-artifacts.ps1",
    "scripts/release/create-signed-tag.ps1"
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file) -or ((Get-Item $file).Length -eq 0)) {
        throw "release-governance file missing or empty: $file"
    }
}

function Assert-Text($File, $Text) {
    if (-not ((Get-Content $File -Raw).Contains($Text))) {
        throw "required text missing in ${File}: $Text"
    }
}

Assert-Text "Cargo.toml" 'repository = "https://github.com/peavey2787/hydra-msg"'
Assert-Text "Cargo.toml" 'rust-version = "1.88"'
Assert-Text "SECURITY.md" 'https://github.com/peavey2787/hydra-msg/security/advisories/new'
Assert-Text "docs/validation/release/release-artifacts.md" 'scripts/release/create-release-package.sh'
Assert-Text "docs/validation/release/release-signing.md" 'scripts/release/sign-release-artifacts.sh'
Assert-Text "docs/validation/release/sbom.md" 'scripts/release/generate-sbom.py'
Assert-Text "docs/validation/release/reproducible-builds.md" 'SOURCE_DATE_EPOCH'
Assert-Text "docs/validation/release/msrv-policy.md" 'rust-version = "1.88"'

$badPattern = 'example\.invalid|fake security email|Production release blocker until verified|must be verified before production release|public production release remains blocked until.*private reporting|GitHub Private Vulnerability Reporting availability is unverified'
foreach ($root in @("README.md", "SECURITY.md", "docs", "CHANGELOG.md")) {
    if (-not (Test-Path $root)) { continue }
    $matches = Select-String -Path (Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue) -Pattern $badPattern -ErrorAction SilentlyContinue
    if ($matches) { throw "stale release-governance blocker or placeholder wording found" }
}

Write-Host "release governance checks passed"
