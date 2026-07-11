# Static regression gate for persistence crash-consistency coverage.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required crash-consistency file missing: $Path"
    }
}

function Assert-TextPresent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (!(Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet)) {
        throw "Crash-consistency invariant missing from ${Path}: $Text"
    }
}

$nativeStore = "crates/hydra-msg/src/persistence/native_store.rs"
$storage = "crates/hydra-msg/src/api/storage.rs"
$identity = "crates/hydra-msg/src/api/identity.rs"
$contacts = "crates/hydra-msg/src/api/contacts.rs"
$messages = "crates/hydra-msg/src/messages/mod.rs"
$crashTests = "crates/hydra-msg/src/tests/crash_consistency.rs"
$wasmApp = "examples/mobile_perf_web/web/app.js"
$wasmHost = "examples/mobile_perf_web/src/main.rs"
$audit = "docs/validation/evidence/crash-consistency-matrix.md"

foreach ($path in @(
    $nativeStore,
    $storage,
    $identity,
    $contacts,
    $messages,
    $crashTests,
    $wasmApp,
    $wasmHost,
    $audit
)) {
    Assert-FileExists $path
}

foreach ($stage in @(
    "write temp file",
    "sync temp file",
    "rename/replace state",
    "sync parent dir"
)) {
    Assert-TextPresent $nativeStore "test_failpoint(path, `"$stage`")?"
    Assert-TextPresent $crashTests $stage
}

Assert-TextPresent $nativeStore "set_test_failpoint"
Assert-TextPresent $storage "restore_verified_backup_snapshot"
Assert-TextPresent $storage "self.apply_state_snapshot(&previous_snapshot)?"
Assert-TextPresent $identity "self.apply_state_snapshot(&previous_snapshot)"
Assert-TextPresent $contacts "self.apply_state_snapshot(&previous_snapshot)"
Assert-TextPresent $messages "self.apply_state_snapshot(&previous_snapshot)"
Assert-TextPresent $crashTests "crash_before_state_rename_leaves_old_state_authoritative"
Assert-TextPresent $crashTests "crash_temp_file_is_ignored_and_removed_on_next_successful_write"
Assert-TextPresent $crashTests "renamed_state_before_parent_sync_or_rollback_is_openable_and_repairs_guard"
Assert-TextPresent $crashTests "parent_dir_sync_failure_returns_error_but_leaves_openable_state"
Assert-TextPresent $crashTests "rollback_evidence_write_failure_leaves_state_openable_and_repairable"
Assert-TextPresent $crashTests "backup_import_failure_is_atomic_in_memory_and_on_disk"
Assert-TextPresent $crashTests "delete_identity_failure_restores_memory_and_disk"
Assert-TextPresent $crashTests "delete_contact_failure_restores_memory_and_disk"
Assert-TextPresent $crashTests "delete_message_failure_restores_memory_and_disk"

Assert-TextPresent $wasmApp "runCrashConsistencyProbe"
Assert-TextPresent $wasmApp "browser-wasm-indexeddb-crash-consistency-matrix"
Assert-TextPresent $wasmApp "IndexedDB flush durability is tested by aborting the write transaction"
Assert-TextPresent $wasmApp "IndexedDB quota error handling is tested"
Assert-TextPresent $wasmApp "browser tab close mid-flush"
Assert-TextPresent $wasmApp "QuotaExceededError"
Assert-TextPresent $wasmApp "tx.abort()"
Assert-TextPresent $wasmHost 'data-action="crash-consistency"'
Assert-TextPresent "docs/spec/threat-model.md" "crash-consistency-matrix.md"

Write-Host "crash-consistency matrix checks passed." -ForegroundColor Green
