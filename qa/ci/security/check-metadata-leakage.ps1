# HYDRA-MSG metadata-leakage gate.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Require-File($Path) {
    if (-not (Test-Path $Path)) {
        throw "required metadata-leakage file missing: $Path"
    }
}

function Require-Text($Path, $Text) {
    if (-not (Select-String -Path $Path -SimpleMatch $Text -Quiet)) {
        throw "metadata-leakage invariant missing from ${Path}: $Text"
    }
}

function Reject-Text($Path, $Text) {
    if (Select-String -Path $Path -SimpleMatch $Text -Quiet) {
        throw "forbidden metadata-leakage pattern found in ${Path}: $Text"
    }
}

$audit = "docs/validation/evidence/metadata-leakage-audit.md"
$threat = "docs/spec/threat-model.md"
$release = "docs/validation/release/release-criteria.md"
$qaGate = "docs/validation/gates/production-qa-gate.md"
$wasm = "crates/hydra-msg-wasm/src/lib.rs"
$wasmTypes = "crates/hydra-msg-wasm/src/types.rs"
$wasmPersistence = "crates/hydra-msg/src/browser/persistence.rs"
$wasmPersistenceJs = "crates/hydra-msg/src/browser/persistence_js.rs"
$wasmDocs = "docs/impl/wasm-javascript-bindings.md"
$apiDocs = "docs/spec/public-developer-api.md"
$authDocs = "docs/spec/anonymous-auth.md"
$storageCodec = "crates/hydra-msg/src/codec/storage.rs"
$statusFile = "crates/hydra-msg/src/persistence/status.rs"
$lobbyRouting = "crates/hydra-msg/src/lobby/routing.rs"

@($audit, $threat, $release, $qaGate, $wasm, $wasmTypes, $wasmPersistence, $wasmPersistenceJs, $wasmDocs, $apiDocs, $authDocs, $storageCodec, $statusFile, $lobbyRouting) | ForEach-Object { Require-File $_ }

@("packet count", "timing", "routing", "anonymous-auth", "browser persistence", "Backup metadata", "not fully unlinkable", "blind credentials", "ZK nullifier", "not metadata-free") | ForEach-Object { Require-Text $audit $_ }

Require-Text $wasmTypes "js_name = routingHint"
Require-Text $wasm "js_name = storageDebugStatus"
Require-Text $wasmPersistenceJs "revision: nextRevision"
Require-Text $wasmPersistenceJs "adapterVersion: HYDRA_ADAPTER_VERSION"
Require-Text $storageCodec "STORAGE_CHUNK_PLAINTEXT_BYTES"
Require-Text $statusFile "HydraStorageDebugStatus"
Require-Text $lobbyRouting "routing_hint()"
Require-Text $authDocs "not fully unlinkable"
Require-Text $authDocs "bearer-token"
Require-Text $authDocs "blind credentials"
Require-Text $authDocs "ZK nullifier"
Require-Text $threat "metadata-leakage-audit.md"
Require-Text $release "metadata-leakage"
Require-Text $qaGate "metadata-leakage"
Require-Text $wasmDocs "routingHint"
Require-Text $apiDocs "routing_hint"

Reject-Text $wasmPersistence "updatedAtMs"
Reject-Text $wasmPersistenceJs "updatedAtMs"
Reject-Text "examples/mobile_perf_web/web/app.js" "updatedAtMs"

Write-Host "metadata-leakage checks passed." -ForegroundColor Green
