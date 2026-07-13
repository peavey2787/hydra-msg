Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-TextInAnyFile($Paths, $Text, $Description) {
    foreach ($Path in $Paths) {
        if (Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet) {
            return
        }
    }
    throw "${Description}: $Text"
}

function Test-TextInAnyFile($Paths, $Text) {
    foreach ($Path in $Paths) {
        if (Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet) {
            return $true
        }
    }
    return $false
}

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
$PersistenceFacade = "crates/hydra-msg/src/browser/persistence.rs"
$PersistenceJs = "crates/hydra-msg/src/browser/persistence_js.rs"
$PersistenceSources = @($PersistenceFacade, $PersistenceJs)
Assert-FileExists $Package
Assert-FileExists $PackageLock
Assert-FileExists $Config
Assert-FileExists $BrowserInstaller
Assert-FileExists $OriginServer
Assert-FileExists $Spec
foreach ($Path in $PersistenceSources) { Assert-FileExists $Path }
Assert-Text $Package "@playwright/test"
if (Select-String -LiteralPath $Spec -SimpleMatch "about:blank" -Quiet) {
    throw "Browser E2E storage tests must use a real HTTP origin, not about:blank"
}

foreach ($Text in @("function transactionFailure", "tx.onabort = () => reject")) {
    Assert-Text $Spec $Text
    Assert-TextInAnyFile $PersistenceSources $Text "Production browser adapter marker missing"
}
foreach ($Text in @(
    "readCurrentRevision",
    "readonly transaction",
    "never acquires an IndexedDB write lock",
    "Recheck inside the readwrite transaction",
    "uniqueDatabaseName",
    "capturedSaveError",
    "saveReadwriteTransactions",
    "let dbPromise = null",
    "databaseOpens",
    "Do not abort or queue a semantic no-op"
)) { Assert-Text $Spec $Text }
foreach ($Text in @(
    "readHydraCurrentRevision",
    "readonly transaction",
    "avoids acquiring a cross-tab write lock",
    "Recheck atomically inside the write transaction",
    "let hydraDbPromise = null",
    "async function hydraIndexedDb()",
    "Reuse one connection per browser realm",
    "No write request is queued"
)) { Assert-TextInAnyFile $PersistenceSources $Text "Production browser adapter marker missing" }
foreach ($Text in @(
    "settleStaleTransactionOnComplete",
    "settleHydraStaleTransactionOnComplete",
    "queueNoOpSettlement",
    "queueHydraNoOpSettlement",
    "abortStaleTransactionAndWait",
    "abortHydraStaleTransactionAndWait",
    "rejectAndAbortStaleTransaction",
    "rejectAndAbortHydraStaleTransaction"
)) {
    if ((Select-String -LiteralPath $Spec -SimpleMatch $Text -Quiet) -or
        (Test-TextInAnyFile $PersistenceSources $Text)) {
        throw "Obsolete stale-CAS settlement strategy remains: $Text"
    }
}

# A per-operation open/close cycle can leave Firefox connections close-pending
# and block the next tab. The harness has a versionchange close and an explicit
# teardown close; production retains only the versionchange safety handler.
$SpecCloseCount = (Select-String -LiteralPath $Spec -SimpleMatch "db.close();").Count
$ProductionCloseCount = 0
foreach ($Path in $PersistenceSources) {
    $ProductionCloseCount += (Select-String -LiteralPath $Path -SimpleMatch "db.close();").Count
}
if ($SpecCloseCount -ne 2) {
    throw "Browser E2E harness must close its cached IndexedDB connection on versionchange and explicit teardown"
}
if ($ProductionCloseCount -ne 1) {
    throw "Production browser adapter must close its cached IndexedDB connection only on versionchange"
}
foreach ($Text in @(
    "async function closeLifecyclePage",
    "window.__hydraLifecycle?.close()",
    "page.close({ runBeforeUnload: false })",
    "await Promise.all([closeLifecyclePage(pageA), closeLifecyclePage(pageB)])"
)) { Assert-Text $Spec $Text }

foreach ($Text in @(
    "baseURL",
    "webServer",
    "serve-test-origin.mjs",
    "HYDRA_BROWSER_WORKERS",
    "workers: workerCount",
    "trace: 'on-first-retry'",
    "playwright-report"
)) { Assert-Text $Config $Text }

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
