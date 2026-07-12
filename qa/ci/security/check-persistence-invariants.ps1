# HYDRA-MSG persistence invariant checks.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-SourceText {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $content = Get-Content $File -Raw
    if (!$content.Contains($Text)) {
        throw "persistence invariant missing: $Description; expected '$Text' in $File"
    }
}

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path $Path -PathType Leaf)) {
        throw "persistence invariant required file missing: $Path"
    }
}

function Get-SearchFiles {
    param([Parameter(Mandatory = $true)][string[]]$Roots)
    foreach ($root in $Roots) {
        if (Test-Path $root -PathType Leaf) {
            Get-Item $root
        } elseif (Test-Path $root -PathType Container) {
            Get-ChildItem $root -Recurse -File |
                Where-Object {
                    $_.FullName -notmatch '[\\/]target[\\/]' -and
                    $_.FullName -notmatch '[\\/]\.git[\\/]' -and
                    $_.Extension -notin @('.bin', '.hex', '.png', '.jpg', '.jpeg', '.gif', '.zip')
                }
        }
    }
}

function Assert-NoSearchMatch {
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $matches = Get-SearchFiles $Roots | Select-String -Pattern $Pattern -ErrorAction SilentlyContinue
    if ($matches) {
        $matches | ForEach-Object { Write-Host $_ }
        throw "persistence invariant forbidden pattern found: $Description"
    }
}

$SnapshotFile = "crates/hydra-msg/src/persistence/snapshot.rs"
$StorageFile = "crates/hydra-msg/src/api/storage.rs"
$CodecStorageFile = "crates/hydra-msg/src/codec/storage.rs"
$WasmPersistenceFile = "crates/hydra-msg/src/browser/persistence.rs"
$WasmPersistenceJsFile = "crates/hydra-msg/src/browser/persistence_js.rs"
$StorageTestsFile = "crates/hydra-msg/src/tests/storage.rs"
$PersistenceTestsFile = "crates/hydra-msg/src/tests/persistence.rs"
$ParserVectorRoot = "qa/vectors/persistence/parser-stress"
$PositiveVectorRoot = "qa/vectors/persistence/positive"
$NegativeVectorRoot = "qa/vectors/persistence/negative"
$PersistenceVectorRoot = "qa/vectors/persistence"

foreach ($path in @($SnapshotFile, $StorageFile, $CodecStorageFile, $WasmPersistenceFile, $WasmPersistenceJsFile, $StorageTestsFile, $PersistenceTestsFile, "$ParserVectorRoot/manifest.sha3-256", "$PositiveVectorRoot/manifest.sha3-256", "$NegativeVectorRoot/manifest.sha3-256", "$PersistenceVectorRoot/manifest.sha3-256")) {
    Assert-FileExists $path
}

Assert-SourceText $SnapshotFile "MAX_IDENTITIES" "snapshot collection-count guardrail"
Assert-SourceText $SnapshotFile "MAX_CONTACTS" "contact collection-count guardrail"
Assert-SourceText $SnapshotFile "MAX_MESSAGES" "message collection-count guardrail"
Assert-SourceText $SnapshotFile "MAX_LOBBIES" "lobby collection-count guardrail"
Assert-SourceText $SnapshotFile "MAX_ANONYMOUS_AUTH_SPENT" "anonymous-auth collection-count guardrail"
Assert-SourceText $SnapshotFile "HashSet" "duplicate collection record detection"
Assert-SourceText $SnapshotFile "reject_duplicate_collection_record" "duplicate collection record rejection helper"
Assert-SourceText $SnapshotFile "reject_collection_limit" "collection limit rejection helper"
Assert-SourceText $SnapshotFile "state record kind" "unknown snapshot record rejection"
Assert-SourceText $PersistenceTestsFile "persistence_parser_stress_vectors_reject_malformed_containers" "parser-stress fixture regression test"
Assert-SourceText $PersistenceTestsFile "state_snapshot_validation_rejects_duplicates_unknowns_and_collection_replays" "snapshot duplicate/unknown regression test"
Assert-SourceText $PersistenceTestsFile "current_persistence_vectors_use_chunked_storage_and_round_trip" "current chunked persistence regression test"
Assert-SourceText $PersistenceTestsFile "old_format_persistence_envelopes_fail_closed" "old-format persistence fail-closed regression test"
Assert-SourceText $PersistenceTestsFile "frozen_persistence_stale_generation_and_restore_floor_vectors_hold" "stale-generation and restore-floor vector regression test"
Assert-SourceText $StorageFile "verify_backup(" "passworded backup verification facade retained"
Assert-SourceText $StorageFile "open_verified_backup_snapshot(bytes.as_ref(), password.as_ref())" "backup verification authenticates with supplied password"
Assert-SourceText $CodecStorageFile "reject_oversize_envelope" "encrypted envelope size limit retained"
Assert-SourceText $CodecStorageFile "reject_long_envelope_lines" "encrypted envelope line-length limit retained"
Assert-SourceText $WasmPersistenceJsFile "indexedDB" "WASM persistence uses IndexedDB"
Assert-SourceText $WasmPersistenceFile "opaque" "WASM persistence adapter documents opaque encrypted bytes"

Assert-NoSearchMatch @("crates", "examples") 'localStorage[.\[]' "direct localStorage use for HYDRA state"
Assert-NoSearchMatch @("crates", "examples") 'state\.(json|txt)|plaintext_state|HYDRA-MSG-STATE-V|STATE_V' "legacy plaintext or numbered state format resurrection"
Assert-NoSearchMatch @("crates/hydra-msg-wasm", "examples", "docs/spec", "docs/impl", "docs/validation", "README.md") 'WasmHydra\.open(Default)?\s*\(' "durable-looking WASM no-op open path"
Assert-NoSearchMatch @("crates", "docs/spec", "docs/impl", "docs/validation", "README.md") 'verify_backup\([^,)]*\)|verifyBackup\([^,)]*\)' "stale one-argument backup verification reference"
Assert-NoSearchMatch @("crates/hydra-msg-wasm", "examples/mobile_perf_web") 'openDatabase|sql\.js|sqlite|localforage' "browser SQLite/WebSQL/localForage persistence detour"

$parserMatches = Get-SearchFiles @("crates/hydra-msg/src") |
    Select-String -Pattern 'fn parse_chunked_storage|fn state_snapshot_text' -ErrorAction SilentlyContinue
$unexpectedParsers = $parserMatches | Where-Object {
    $_.Path -notlike "*crates/hydra-msg/src/codec/storage.rs" -and
    $_.Path -notlike "*crates/hydra-msg/src/persistence/snapshot/helpers.rs"
}
if ($unexpectedParsers) {
    $unexpectedParsers | ForEach-Object { Write-Host $_ }
    throw "duplicate snapshot/envelope parser found outside canonical owners"
}

$parserVectorCount = @(Get-ChildItem $ParserVectorRoot -Recurse -Filter metadata.json).Count
if ($parserVectorCount -lt 5) {
    throw "expected at least 5 persistence parser-stress vectors, found $parserVectorCount"
}
$positiveVectorCount = @(Get-ChildItem $PositiveVectorRoot -Recurse -Filter metadata.json).Count
if ($positiveVectorCount -lt 2) {
    throw "expected at least 2 positive persistence vectors, found $positiveVectorCount"
}
$negativeVectorCount = @(Get-ChildItem $NegativeVectorRoot -Recurse -Filter metadata.json).Count
if ($negativeVectorCount -lt 6) {
    throw "expected at least 6 negative persistence vectors, found $negativeVectorCount"
}
foreach ($vectorId in @(
    "TV-PERSISTENCE-STATE-BAD-MAGIC",
    "TV-PERSISTENCE-STATE-EMPTY-CIPHERTEXT",
    "TV-PERSISTENCE-BACKUP-BAD-KDF",
    "TV-PERSISTENCE-BACKUP-BAD-NONCE",
    "TV-PERSISTENCE-SNAPSHOT-DUPLICATE-SCALAR"
)) {
    $metadata = "$ParserVectorRoot/$vectorId/metadata.json"
    Assert-FileExists $metadata
    Assert-SourceText $metadata '"expected_result":"reject"' "$vectorId expected rejection metadata"
}

foreach ($vectorId in @(
    "TV-PERSIST-EMPTY-000",
    "TV-PERSIST-FULL-000"
)) {
    $metadata = "$PositiveVectorRoot/$vectorId/metadata.json"
    Assert-FileExists $metadata
    Assert-SourceText $metadata '"expected_result"' "$vectorId expected acceptance metadata"
}
foreach ($vectorId in @(
    "TV-PERSIST-WRONG-PASSWORD-000",
    "TV-PERSIST-BAD-KDF-PARAMS-000",
    "TV-PERSIST-CIPHERTEXT-FLIP-000",
    "TV-PERSIST-TRUNCATED-000",
    "TV-PERSIST-BAD-SNAPSHOT-000",
    "TV-PERSIST-STALE-GENERATION-000"
)) {
    $metadata = "$NegativeVectorRoot/$vectorId/metadata.json"
    Assert-FileExists $metadata
    Assert-SourceText $metadata '"expected_result":"reject"' "$vectorId expected rejection metadata"
}

Write-Host "persistence invariant checks passed" -ForegroundColor Green
