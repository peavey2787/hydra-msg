Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-FileExists($Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required browser E2E file missing: $Path"
    }
}

function Assert-Text($Path, $Text) {
    if (!(Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet)) {
        throw "Browser E2E scenario missing from ${Path}: $Text"
    }
}

$Package = "qa/browser/playwright/package.json"
$PackageLock = "qa/browser/playwright/package-lock.json"
$Config = "qa/browser/playwright/playwright.config.mjs"
$BrowserInstaller = "qa/browser/playwright/scripts/install-browsers.mjs"
$OriginServer = "qa/browser/playwright/scripts/serve-test-origin.mjs"
$Spec = "qa/browser/playwright/tests/browser-lifecycle.spec.mjs"
Assert-FileExists $Package
Assert-FileExists $PackageLock
Assert-FileExists $Config
Assert-FileExists $BrowserInstaller
Assert-FileExists $OriginServer
Assert-FileExists $Spec
Assert-Text $Package "@playwright/test"
if (Select-String -LiteralPath $Spec -SimpleMatch "about:blank" -Quiet) {
    throw "Browser E2E storage tests must use a real HTTP origin, not about:blank"
}
foreach ($Text in @("baseURL", "webServer", "serve-test-origin.mjs")) {
    Assert-Text $Config $Text
}

foreach ($Text in @(
    "IndexedDB unavailable/private-mode style denial",
    "QuotaExceededError",
    "compare-and-swap rejects stale two-tab writes",
    "delete-while-open",
    "aborted tab-crash-style transaction",
    "reload with dirty in-memory state",
    "mobile pagehide handler",
    "persistent storage denial and grant",
    "HYDRA_BROWSER_TEST_URL"
)) { Assert-Text $Spec $Text }

if ($env:HYDRA_RUN_BROWSER_E2E -ne "1") {
    Write-Host "Browser E2E static checks passed. Set HYDRA_RUN_BROWSER_E2E=1 to run Playwright."
    exit 0
}

if (!(Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm is required for HYDRA_RUN_BROWSER_E2E=1"
}

Set-Location "qa/browser/playwright"
& npm ci
if ($LASTEXITCODE -ne 0) {
    throw "Playwright npm dependency installation failed"
}

if ($env:HYDRA_SKIP_PLAYWRIGHT_INSTALL -eq "1") {
    Write-Host "Skipping Playwright browser binary install because HYDRA_SKIP_PLAYWRIGHT_INSTALL=1"
} else {
    & npm run install:browsers
    if ($LASTEXITCODE -ne 0) {
        throw "Playwright browser installation failed"
    }
}

& npx playwright test
if ($LASTEXITCODE -ne 0) {
    throw "Playwright browser lifecycle tests failed"
}
