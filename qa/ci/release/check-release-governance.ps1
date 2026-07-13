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
    ".github/workflows/ci.yml",
    ".github/workflows/release-validation.yml",
    ".github/dependabot.yml",
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
Assert-Text ".github/workflows/ci.yml" "push:"
Assert-Text ".github/workflows/ci.yml" "pull_request:"
Assert-Text ".github/workflows/ci.yml" "workflow_dispatch:"
Assert-Text ".github/workflows/ci.yml" "Core bounded CI"
Assert-Text ".github/workflows/ci.yml" "./qa/ci/core/check-tests.sh --skip-vectors --skip-release-static"
Assert-Text ".github/workflows/ci.yml" "./qa/ci/core/check-examples.sh"
Assert-Text ".github/workflows/ci.yml" "Browser lifecycle"
Assert-Text ".github/workflows/ci.yml" 'HYDRA_RUN_BROWSER_E2E: "1"'
Assert-Text ".github/workflows/ci.yml" "./qa/ci/reliability/check-browser-e2e.sh"
Assert-Text ".github/workflows/ci.yml" "Deterministic fuzz regression"
Assert-Text ".github/workflows/ci.yml" "./qa/ci/fuzz/check-fuzz.sh"
Assert-Text ".github/workflows/ci.yml" 'HYDRA_CI_EPHEMERAL_LOCK_REFRESH: "1"'
Assert-Text ".github/workflows/ci.yml" "cargo fetch"
Assert-Text ".github/workflows/ci.yml" "target/ci-logs/core.log"
Assert-Text ".github/workflows/ci.yml" "target/ci-logs/browser-lifecycle.log"
Assert-Text ".github/workflows/ci.yml" "target/ci-logs/fuzz-regression.log"
Assert-Text "qa/ci/core/check-rust.sh" "cargo metadata --locked"
Assert-Text "qa/ci/security/check-supply-chain.sh" "cargo fetch --locked"
Assert-Text "qa/ci/fuzz/check-fuzz.sh" "cargo run --locked -p hydra-fuzz-gate --"
Assert-Text "qa/ci/check-all.sh" 'fuzz_mode=${HYDRA_FUZZ_MODE:-smoke}'
Assert-Text "qa/ci/check-all.sh" 'fuzz_runs=${fuzz_runs:-256}'
Assert-Text "qa/ci/check-all.sh" "--overnight"
Assert-Text "qa/ci/check-all.sh" "--deep-fuzz"
Assert-Text "qa/ci/fuzz/check-fuzz.sh" "message_stateful_flow"
Assert-Text "crates/hydra-msg/Cargo.toml" "fuzzing = []"
Assert-Text "qa/fuzz/cargo-fuzz/Cargo.toml" 'features = ["fuzzing"]'
Assert-Text "qa/fuzz/cargo-fuzz/fuzz_targets/message_codec.rs" "fuzzing::decode_message_payload"
Assert-Text "qa/fuzz/cargo-fuzz/fuzz_targets/message_stateful_flow.rs" "common::paired"
Assert-Text ".github/workflows/ci.yml" 'tee -a "$log_file"'
Assert-Text ".github/workflows/ci.yml" "GITHUB_STEP_SUMMARY"
Assert-Text ".github/workflows/release-validation.yml" "workflow_dispatch:"
Assert-Text ".github/workflows/release-validation.yml" "./qa/ci/check-all.sh"
Assert-Text ".github/workflows/release-validation.yml" "target/ci-logs/release-check-all.log"
Assert-Text ".github/workflows/release-validation.yml" "Full sequential release check-all"
Assert-Text ".github/workflows/release-validation.yml" "cargo install cargo-mutants --locked"
Assert-Text ".github/workflows/release-validation.yml" "cargo install cargo-fuzz --locked"
Assert-Text ".github/workflows/release-validation.yml" 'tee -a "$log_file"'
Assert-Text ".github/workflows/release-validation.yml" "HYDRA_RELEASE_FUZZ_RUNS"
Assert-Text ".github/workflows/release-validation.yml" "--deep-fuzz"
Assert-Text ".github/workflows/release-validation.yml" "HYDRA_RELEASE_MUTATION_JOBS"
Assert-Text ".github/workflows/release-validation.yml" "GITHUB_STEP_SUMMARY"
Assert-Text ".github/dependabot.yml" "package-ecosystem: github-actions"

if (Select-String -Path "qa/fuzz/cargo-fuzz/fuzz_targets/message_codec.rs" -Pattern 'common::(paired|fresh|temp_case_dir)|import_messages' -Quiet) {
    throw "fast message_codec fuzz target must remain in-memory and stateless"
}

$badTempArtifactPath = Get-ChildItem ".github/workflows" -Filter "*.yml" -File |
    Select-String -SimpleMatch '${{ runner.temp }}/hydra-ci-logs'
if ($badTempArtifactPath) {
    throw "GitHub artifact logs must stay under github.workspace, not runner.temp"
}

$lockMutation = Get-ChildItem "qa/ci" -Include "*.sh", "*.ps1" -Recurse -File |
    Where-Object { $_.Name -notin @("check-release-governance.sh", "check-release-governance.ps1") } |
    Select-String -Pattern 'rm -f Cargo\.lock|Remove-Item.*Cargo\.lock|cargo generate-lockfile'
$workflowLockMutation = Get-ChildItem ".github/workflows" -Include "*.yml", "*.yaml" -Recurse -File |
    Select-String -Pattern 'rm -f Cargo\.lock|Remove-Item.*Cargo\.lock|cargo generate-lockfile'
if ($lockMutation -or $workflowLockMutation) {
    $lockMutation | ForEach-Object { Write-Host $_ }
    $workflowLockMutation | ForEach-Object { Write-Host $_ }
    throw "CI must validate the committed Cargo.lock with --locked; workflows and local QA scripts must not rewrite it."
}

$unpinnedActions = Get-ChildItem ".github/workflows" -Filter "*.yml" -File |
    Select-String -Pattern '^\s*uses:\s+\S+@' |
    Where-Object { $_.Line -notmatch '@[0-9a-fA-F]{40}(\s|#|$)' }
if ($unpinnedActions) {
    $unpinnedActions | ForEach-Object { Write-Host $_ }
    throw "GitHub Actions must be pinned to immutable 40-character commit SHAs"
}
foreach ($workflow in @(".github/workflows/ci.yml", ".github/workflows/release-validation.yml")) {
    Assert-Text $workflow "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
    Assert-Text $workflow "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
}
Assert-Text ".github/workflows/ci.yml" "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0"
Assert-Text ".github/workflows/release-validation.yml" "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0"

$badPattern = 'example\.invalid|fake security email|Production release blocker until verified|must be verified before production release|public production release remains blocked until.*private reporting|GitHub Private Vulnerability Reporting availability is unverified'
foreach ($root in @("README.md", "SECURITY.md", "docs", "CHANGELOG.md")) {
    if (-not (Test-Path $root)) { continue }
    $matches = Select-String -Path (Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue) -Pattern $badPattern -ErrorAction SilentlyContinue
    if ($matches) { throw "stale release-governance blocker or placeholder wording found" }
}

Write-Host "release governance checks passed"
