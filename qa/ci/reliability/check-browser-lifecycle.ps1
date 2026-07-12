# Static regression gate for WASM/browser lifecycle persistence policy.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required browser lifecycle file missing: $Path"
    }
}

function Assert-TextPresent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (!(Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet)) {
        throw "Browser lifecycle invariant missing from ${Path}: $Text"
    }
}

function Assert-TextAbsent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet) {
        throw "Forbidden browser lifecycle pattern found in ${Path}: $Text"
    }
}


function Assert-TextPresentInAny {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$Text
    )
    foreach ($Path in $Paths) {
        if (Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet) {
            return
        }
    }
    throw "Browser lifecycle invariant missing from browser persistence adapter: $Text"
}

function Assert-TextAbsentFromAll {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$Text
    )
    foreach ($Path in $Paths) {
        if (Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet) {
            throw "Forbidden browser lifecycle pattern found in ${Path}: $Text"
        }
    }
}

$wasm = "crates/hydra-msg-wasm/src/lib.rs"
$adapterFacade = "crates/hydra-msg/src/browser/persistence.rs"
$adapterJs = "crates/hydra-msg/src/browser/persistence_js.rs"
$adapterSources = @($adapterFacade, $adapterJs)
$wasmDocs = "crates/hydra-msg-wasm/README.md"
$implDocs = "docs/impl/wasm-javascript-bindings.md"
$apiDocs = "docs/spec/public-developer-api.md"
$app = "examples/mobile_perf_web/web/app.js"
$hostFile = "examples/mobile_perf_web/src/main.rs"
$audit = "docs/validation/evidence/wasm-browser-lifecycle-policy.md"

foreach ($path in @($wasm, $adapterFacade, $adapterJs, $wasmDocs, $implDocs, $apiDocs, $app, $hostFile, $audit)) {
    Assert-FileExists $path
}

foreach ($text in @(
    "const HYDRA_DB_VERSION = 2",
    "revision: nextRevision",
    "hydraIndexedDbSave(name, bytes, expectedRevision)",
    "currentRevision !== expectedRevision",
    "persistent record revision missing",
    "staleHydraProfileError",
    "last-writer-wins",
    "storage.persist",
    "hydraBrowserLifecycleStatus",
    "IndexedDB unavailable for HYDRA persistent state"
)) { Assert-TextPresentInAny $adapterSources $text }

foreach ($text in @(
    "persistent_revision: Option<u64>",
    "js_name = persistentRevision",
    "js_name = browserLifecycleStatus",
    "js_name = requestPersistentStorage",
    "flush_browser_persistent",
    "open_browser_persistent"
)) { Assert-TextPresent $wasm $text }

foreach ($text in @(
    "runMultiTabConcurrencyProbe",
    "browser-wasm-indexeddb-multi-tab-concurrency",
    "stale tab flush must be rejected instead of using last-writer-wins",
    "WasmHydra.browserLifecycleStatus",
    "WasmHydra.requestPersistentStorage",
    "const DB_VERSION = 2"
)) { Assert-TextPresent $app $text }
Assert-TextPresent $hostFile 'data-action="multi-tab"'

foreach ($text in @(
    "Private browsing",
    "Storage eviction",
    "QuotaExceededError",
    "Multiple tabs",
    "Tab crash during flush",
    "Versioned DB format",
    "Browser denying persistent storage",
    "Mobile background"
)) { Assert-TextPresent $audit $text }

Assert-TextPresent $implDocs "compare-and-swap"
Assert-TextPresent $implDocs "last-writer-wins"
Assert-TextPresent $implDocs "browserLifecycleStatus"
Assert-TextPresent $implDocs "requestPersistentStorage"
Assert-TextPresent $apiDocs "profile-revision compare-and-swap"
Assert-TextPresent "docs/spec/threat-model.md" "wasm-browser-lifecycle-policy.md"

Assert-TextAbsentFromAll $adapterSources "localStorage."
Assert-TextAbsentFromAll $adapterSources "localStorage["
Assert-TextAbsentFromAll $adapterSources "updatedAtMs"
Assert-TextAbsent $app "updatedAtMs"
Assert-TextAbsent $app "last writer wins"

& .\qa\ci\reliability\check-browser-e2e.ps1
Write-Host "WASM/browser lifecycle checks passed." -ForegroundColor Green
