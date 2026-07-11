# HYDRA-MSG mobile/browser persistence benchmark static checks.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

$AppJs = "examples/mobile_perf_web/web/app.js"
$ServerRs = "examples/mobile_perf_web/src/main.rs"

function Assert-SourceText {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $content = Get-Content $File -Raw
    if (!$content.Contains($Text)) {
        throw "mobile perf web check missing: $Description; expected '$Text' in $File"
    }
}

function Assert-NoSourceText {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $content = Get-Content $File -Raw
    if ($content.Contains($Text)) {
        throw "mobile perf web check found forbidden text: $Description; forbidden '$Text' in $File"
    }
}

if (!(Test-Path $AppJs)) {
    throw "missing browser benchmark app: $AppJs"
}
if (!(Test-Path $ServerRs)) {
    throw "missing mobile perf host: $ServerRs"
}

Assert-SourceText $ServerRs 'src="/app.js"' "external browser benchmark script"
Assert-SourceText $ServerRs 'include_str!("../web/app.js")' "host serves the browser benchmark script"
Assert-SourceText $ServerRs '/pkg-health' "WASM package health endpoint"
Assert-SourceText $ServerRs 'env!("CARGO_MANIFEST_DIR")' "runtime-independent WASM pkg path"
Assert-SourceText $ServerRs 'data-action="multi-tab"' "multi-tab concurrency button"

Assert-SourceText $AppJs 'ensureWasmPackageAvailable' "WASM package preflight check"
Assert-SourceText $AppJs 'WASM_JS_PATH' "centralized WASM JS path"
Assert-SourceText $AppJs 'WASM_BG_PATH' "centralized WASM binary path"
Assert-SourceText $AppJs 'openEphemeral(EPHEMERAL_PROFILE, STATE_PASSWORD)' "passworded ephemeral benchmark open"
Assert-SourceText $AppJs 'openPersistent(PERSISTENT_PROFILE, STATE_PASSWORD)' "passworded persistent benchmark open"
Assert-SourceText $AppJs 'openPersistent(RESTORE_PROFILE, STATE_PASSWORD)' "passworded restore-profile open"
Assert-SourceText $AppJs 'openEphemeral(`${EPHEMERAL_PROFILE}-persistence-peer-' "separate ephemeral peer for persistent send/receive validation"
Assert-SourceText $AppJs 'peer.replyHandshake(offer)' "two-instance persistent-suite handshake"
Assert-SourceText $AppJs 'received = peer.receive(packet) || received;' "persistent suite receives with peer session"
Assert-SourceText $AppJs 'await hydra.flush()' "explicit dirty-state flush in persistence suite"
Assert-SourceText $AppJs 'exportBackup(BACKUP_PASSWORD)' "backup export benchmark coverage"
Assert-SourceText $AppJs 'verifyBackup(backup, BACKUP_PASSWORD)' "passworded backup verification benchmark coverage"
Assert-SourceText $AppJs 'importBackup(backup, BACKUP_PASSWORD)' "backup import benchmark coverage"
Assert-SourceText $AppJs 'importBackup must mark restored persistent state dirty until explicit flush' "backup restore dirty-state boundary coverage"
Assert-SourceText $AppJs 'navigator.storage.estimate' "quota estimate probe"
Assert-SourceText $AppJs 'QuotaExceededError' "user-facing quota error path"
Assert-SourceText $AppJs 'runApiMisuseGuard' "browser misuse regression coverage"
Assert-SourceText $AppJs 'runMultiTabConcurrencyProbe' "multi-tab stale-writer regression coverage"
Assert-SourceText $AppJs 'browser-wasm-indexeddb-multi-tab-concurrency' "multi-tab CAS result payload"
Assert-SourceText $AppJs 'stale tab flush must be rejected instead of using last-writer-wins' "multi-tab stale flush rejection"
Assert-SourceText $AppJs 'WasmHydra.browserLifecycleStatus' "browser lifecycle status probe"
Assert-SourceText $AppJs 'WasmHydra.requestPersistentStorage' "persistent storage request probe"
Assert-SourceText $AppJs 'IndexedDB stores opaque encrypted HYDRA snapshot bytes' "opaque-byte storage note"

Assert-NoSourceText $AppJs 'localStorage.' "HYDRA state must not read/write localStorage"
Assert-NoSourceText $AppJs 'localStorage[' "HYDRA state must not read/write localStorage"
Assert-NoSourceText $AppJs 'openDefault' "removed durable-looking WASM alias"
Assert-NoSourceText $AppJs 'WasmHydra.open(' "ambiguous WASM open alias"

$openPersistentMissingPassword = Select-String -Path $AppJs -Pattern 'openPersistent\([^,\n\)]*\)' -ErrorAction SilentlyContinue
if ($openPersistentMissingPassword) {
    $openPersistentMissingPassword | ForEach-Object { Write-Host $_ }
    throw "mobile perf web check found openPersistent call without password argument"
}

$openEphemeralMissingPassword = Select-String -Path $AppJs -Pattern 'openEphemeral\([^,\n\)]*\)' -ErrorAction SilentlyContinue
if ($openEphemeralMissingPassword) {
    $openEphemeralMissingPassword | ForEach-Object { Write-Host $_ }
    throw "mobile perf web check found openEphemeral call without password argument"
}

Write-Host "mobile perf web checks passed" -ForegroundColor Green
