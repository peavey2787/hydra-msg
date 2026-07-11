# Static regression gate for hostile-input and retained-state resource bounds.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
Set-Location $RepoRoot

function Assert-FileExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required resource-limit file missing: $Path"
    }
}

function Assert-TextPresent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (!(Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet)) {
        throw "Resource-limit invariant missing from ${Path}: $Text"
    }
}

function Assert-TextAbsent {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    if (Select-String -LiteralPath $Path -SimpleMatch $Text -Quiet) {
        throw "Forbidden resource-exhaustion pattern found in ${Path}: $Text"
    }
}

$limits = "crates/hydra-msg/src/limits.rs"
$fragments = "crates/hydra-msg/src/packet_fragments/reassembly.rs"
$handshake = "crates/hydra-msg/src/handshake/mod.rs"
$handshakeRouting = "crates/hydra-msg/src/handshake/routing.rs"
$messages = "crates/hydra-msg/src/codec/messages.rs"
$messageTypes = "crates/hydra-msg/src/messages/types.rs"
$storageCodec = "crates/hydra-msg/src/codec/storage.rs"
$nativeStore = "crates/hydra-msg/src/persistence/native_store.rs"
$sessionSnapshot = "crates/hydra-session/src/session/snapshot.rs"
$groupSender = "crates/hydra-group/src/state/sender_chain.rs"
$groupSenderRestore = "crates/hydra-group/src/state/sender_chain/snapshot_restore.rs"
$groupReplay = "crates/hydra-group/src/state/replay.rs"
$audit = "qa/evidence/resource-exhaustion-dos-limits.md"

foreach ($path in @(
    $limits,
    $fragments,
    $handshake,
    $handshakeRouting,
    $messages,
    $messageTypes,
    $storageCodec,
    $nativeStore,
    $sessionSnapshot,
    $groupSender,
    $groupSenderRestore,
    $groupReplay,
    "crates/hydra-msg/src/tests/resource_limits.rs",
    "crates/hydra-group/src/tests/resource_limits.rs",
    $audit
)) {
    Assert-FileExists $path
}

foreach ($constant in @(
    "MAX_PENDING_FRAGMENTS",
    "MAX_PENDING_FRAGMENT_BYTES",
    "MAX_INCOMPLETE_MESSAGES",
    "MAX_INCOMPLETE_MESSAGES_PER_CONTACT",
    "MAX_INCOMPLETE_MESSAGES_PER_LOBBY",
    "MAX_FRAGMENT_AGE_SECS",
    "MAX_CONTACTS",
    "MAX_LOBBIES",
    "MAX_MESSAGES",
    "MAX_MESSAGES_PER_CONTACT",
    "MAX_MESSAGE_IMPORT_BYTES",
    "MAX_STORED_MESSAGE_BYTES",
    "MAX_STORED_MESSAGE_BYTES_PER_CONTACT",
    "MAX_ANONYMOUS_AUTH_SPENT",
    "MAX_ATTACHMENT_BYTES",
    "MAX_BACKUP_BYTES",
    "MAX_IMPORTED_CONTACTS",
    "MAX_HANDSHAKE_OFFER_BYTES",
    "MAX_HANDSHAKE_ANSWER_BYTES",
    "MAX_PENDING_HANDSHAKES",
    "MAX_PENDING_HANDSHAKE_AGE_SECS",
    "MAX_SESSION_ROUTE_TAGS_PER_SESSION",
    "MAX_SESSION_ROUTE_TAGS",
    "MAX_LOBBY_OUTBOUND_PACKETS",
    "MAX_LOBBY_OUTBOUND_ENVELOPE_BYTES"
)) {
    Assert-TextPresent $limits "pub const $constant"
}

Assert-TextPresent $fragments "parts: HashMap<usize, Vec<u8>>"
Assert-TextPresent $fragments "expire_stale_fragments(pending_fragments);"
Assert-TextPresent $fragments "MAX_PENDING_FRAGMENT_BYTES"
Assert-TextPresent $messages "reject_encoded_size(bytes.len(), MAX_PACKED_MESSAGE_BYTES"
Assert-TextPresent $nativeStore "file.take(read_limit).read_to_end"
Assert-TextPresent $messageTypes "file.take(read_limit).read_to_end"
Assert-TextPresent $storageCodec "MAX_BACKUP_BYTES"
Assert-TextPresent $storageCodec "MAX_ENCRYPTED_STATE_BYTES"
Assert-TextPresent $storageCodec "STORAGE_CHUNK_PLAINTEXT_BYTES"
Assert-TextPresent $storageCodec 'reject_trailing_nonempty_lines(&mut lines, "storage trailing data")'
Assert-TextPresent $handshakeRouting "candidate_receive_route_tags"
Assert-TextPresent $handshakeRouting "receive_routes"
Assert-TextPresent $sessionSnapshot "SkippedKeyStore::from_snapshot"
Assert-TextPresent $groupSenderRestore "snapshot.skipped.len() > max_skipped"
Assert-TextPresent $groupReplay "snapshot.accepted_messages.len() > max_accepted"
Assert-TextPresent "crates/hydra-msg/src/tests/resource_limits.rs" "incomplete_fragments_do_not_force_full_state_persistence"
Assert-TextPresent "crates/hydra-msg/src/tests/resource_limits.rs" "route_index_dispatches_to_one_session_and_refreshes_after_receive"
Assert-TextPresent "crates/hydra-msg/src/tests/resource_limits.rs" "encrypted_state_and_backup_reject_trailing_records_before_crypto_work"
Assert-TextPresent "crates/hydra-group/src/tests/resource_limits.rs" "replay_snapshot_rejects_accepted_message_overflow_and_duplicates"
Assert-TextPresent "docs/spec/threat-model.md" "resource-exhaustion-dos-limits.md"

Assert-TextAbsent $fragments "vec![None; part.total]"
Assert-TextAbsent $fragments "Vec::with_capacity(part.total)"
Assert-TextAbsent $handshake ".sessions.iter_mut().find_map"
Assert-TextAbsent $handshakeRouting ".sessions.iter_mut().find_map"

Write-Host "resource-exhaustion/DoS limit checks passed." -ForegroundColor Green
