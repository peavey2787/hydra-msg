#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required resource-limit file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "resource-limit invariant missing from $file: $text" >&2
    exit 1
  fi
}

reject_text() {
  file=$1
  text=$2
  if grep -Fq -- "$text" "$file"; then
    echo "forbidden resource-exhaustion pattern found in $file: $text" >&2
    exit 1
  fi
}

require_pattern() {
  file=$1
  pattern=$2
  description=$3
  if ! tr '\r\n\t' '   ' < "$file" | grep -Eq -- "$pattern"; then
    echo "resource-limit invariant missing from $file: $description" >&2
    exit 1
  fi
}

limits=crates/hydra-msg/src/limits.rs
fragments=crates/hydra-msg/src/packet_fragments/reassembly.rs
handshake=crates/hydra-msg/src/handshake/finish.rs
handshake_codec=crates/hydra-msg/src/codec/handshake.rs
handshake_routing=crates/hydra-msg/src/handshake/routing.rs
messages=crates/hydra-msg/src/codec/messages.rs
message_types=crates/hydra-msg/src/messages/types.rs
storage_codec=crates/hydra-msg/src/codec/storage.rs
native_store=crates/hydra-msg/src/persistence/native_store.rs
session_snapshot=crates/hydra-session/src/session/snapshot.rs
group_sender=crates/hydra-group/src/state/sender_chain.rs
group_sender_restore=crates/hydra-group/src/state/sender_chain/snapshot_restore.rs
group_replay=crates/hydra-group/src/state/replay.rs
stego_api=crates/hydra-stego/src/api.rs
stego_deterministic=crates/hydra-stego/src/deterministic/codec.rs
stego_fast=crates/hydra-stego/src/generative/fast.rs
stego_hybrid=crates/hydra-stego/src/generative/hybrid/codec.rs
stego_generative=crates/hydra-stego/src/generative/mod.rs
stego_process_io=crates/hydra-stego/src/process/io.rs
audit=docs/validation/evidence/resource-exhaustion-dos-limits.md

for file in \
  "$limits" \
  "$fragments" \
  "$handshake" \
  "$handshake_codec" \
  "$handshake_routing" \
  "$messages" \
  "$message_types" \
  "$storage_codec" \
  "$native_store" \
  "$session_snapshot" \
  "$group_sender" \
  "$group_sender_restore" \
  "$group_replay" \
  "$stego_api" \
  "$stego_deterministic" \
  "$stego_fast" \
  "$stego_hybrid" \
  "$stego_generative" \
  "$stego_process_io" \
  crates/hydra-stego/tests/production_api.rs \
  crates/hydra-msg/src/tests/resource_limits.rs \
  crates/hydra-group/src/tests/resource_limits.rs \
  "$audit"
do
  require_file "$file"
done

for constant in \
  MAX_PENDING_FRAGMENTS \
  MAX_PENDING_FRAGMENT_BYTES \
  MAX_INCOMPLETE_MESSAGES \
  MAX_INCOMPLETE_MESSAGES_PER_CONTACT \
  MAX_INCOMPLETE_MESSAGES_PER_LOBBY \
  MAX_FRAGMENT_AGE_SECS \
  MAX_CONTACTS \
  MAX_LOBBIES \
  MAX_MESSAGES \
  MAX_MESSAGES_PER_CONTACT \
  MAX_MESSAGE_IMPORT_BYTES \
  MAX_STORED_MESSAGE_BYTES \
  MAX_STORED_MESSAGE_BYTES_PER_CONTACT \
  MAX_ANONYMOUS_AUTH_SPENT \
  MAX_ATTACHMENT_BYTES \
  MAX_BACKUP_BYTES \
  MAX_IMPORTED_CONTACTS \
  MAX_HANDSHAKE_OFFER_BYTES \
  MAX_HANDSHAKE_ANSWER_BYTES \
  MAX_HANDSHAKE_FINISH_BYTES \
  MAX_PENDING_HANDSHAKES \
  MAX_PENDING_HANDSHAKE_AGE_SECS \
  MAX_SESSION_ROUTE_TAGS_PER_SESSION \
  MAX_SESSION_ROUTE_TAGS \
  MAX_LOBBY_OUTBOUND_PACKETS \
  MAX_LOBBY_OUTBOUND_ENVELOPE_BYTES
 do
  require_text "$limits" "pub const $constant"
done

require_text "$fragments" "parts: HashMap<usize, Vec<u8>>"
require_text "$fragments" "expire_stale_fragments(pending_fragments);"
require_text "$fragments" "MAX_PENDING_FRAGMENT_BYTES"
require_text "$messages" "reject_encoded_size(bytes.len(), MAX_PACKED_MESSAGE_BYTES"
require_text "$native_store" "file.take(read_limit).read_to_end"
require_text "$message_types" "file.take(read_limit).read_to_end"
require_text "$storage_codec" "MAX_BACKUP_BYTES"
require_text "$storage_codec" "MAX_ENCRYPTED_STATE_BYTES"
require_text "$storage_codec" "STORAGE_CHUNK_PLAINTEXT_BYTES"
require_text "$storage_codec" 'reject_trailing_nonempty_lines(&mut lines, "storage trailing data")'
require_text "$handshake_codec" "MAX_HANDSHAKE_FINISH_BYTES"
require_pattern "$handshake_codec" 'reject_encoded_size[[:space:]]*\([[:space:]]*finish\.len\(\)[[:space:]]*,[[:space:]]*MAX_HANDSHAKE_FINISH_BYTES' "FINISH verifier enforces MAX_HANDSHAKE_FINISH_BYTES independent of rustfmt line wrapping"
require_pattern "$handshake" 'reject_encoded_size[[:space:]]*\([[:space:]]*finish\.len\(\)[[:space:]]*,[[:space:]]*MAX_HANDSHAKE_FINISH_BYTES' "public FINISH entry point rejects oversized input before route lookup/crypto"
require_text "$handshake_routing" "candidate_receive_route_tags"
require_text "$handshake_routing" "receive_routes"
require_text "$session_snapshot" "SkippedKeyStore::from_snapshot"
require_text "$group_sender_restore" "snapshot.skipped.len() > max_skipped"
require_text "$group_replay" "snapshot.accepted_messages.len() > max_accepted"
require_text "$stego_deterministic" "MAX_DETERMINISTIC_COVER_BYTES"
require_text "$stego_deterministic" "cover_text.len() > self.maximum_cover_bytes"
require_text "$stego_deterministic" "self.decode_at(&words, 0)?"
require_text "$stego_deterministic" "validate_rendered_record"
require_text "$stego_fast" "maximum_frame_bytes + 1"
require_text "$stego_fast" "ensure_selector_capacity"
require_text "$stego_hybrid" "take(maximum_words + 1)"
require_text "$stego_hybrid" "take(MAX_INTRO_WORDS + 1)"
require_text "$stego_hybrid" "min(MAX_INTRO_WORDS + 1)"
require_text "$stego_hybrid" "ensure_hybrid_capacity"
require_text "$stego_generative" "self.ensure_cover_bytes(cover_text)?;"
require_text "$stego_generative" "target_bits / 2).min"
require_text "$stego_process_io" "recv_timeout(remaining)"
require_text "$stego_process_io" "prepare_request(request)?"
require_text "$stego_process_io" "writer stopped unexpectedly"
require_text "$stego_process_io" "MAX_RESPONSE_BYTES"
require_text crates/hydra-stego/src/process/mod.rs "ensure_hex_request_fits"
require_text crates/hydra-stego/src/process/mod.rs "ensure_token_request_fits"
require_text crates/hydra-stego/tests/production_api.rs "decode_limits_fail_before_unbounded_work"
require_text crates/hydra-msg/src/tests/resource_limits.rs "incomplete_fragments_do_not_force_full_state_persistence"
require_text crates/hydra-msg/src/tests/resource_limits.rs "route_index_dispatches_to_one_session_and_refreshes_after_receive"
require_text crates/hydra-msg/src/tests/resource_limits.rs "encrypted_state_and_backup_reject_trailing_records_before_crypto_work"
require_text crates/hydra-group/src/tests/resource_limits.rs "replay_snapshot_rejects_accepted_message_overflow_and_duplicates"
require_text docs/spec/threat-model.md "resource-exhaustion-dos-limits.md"

reject_text "$fragments" "vec![None; part.total]"
reject_text "$fragments" "Vec::with_capacity(part.total)"
reject_text "$handshake" ".sessions.iter_mut().find_map"
reject_text "$handshake_routing" ".sessions.iter_mut().find_map"

printf 'resource-exhaustion/DoS limit checks passed.\n'
