#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_source_text() {
  file=$1
  text=$2
  description=$3
  if ! grep -Fq "$text" "$file"; then
    echo "persistence invariant missing: $description" >&2
    echo "expected text: $text" >&2
    echo "file: $file" >&2
    exit 1
  fi
}

forbidden_search() {
  roots=$1
  pattern=$2
  description=$3
  matches=$(grep -RInE --exclude-dir=target --exclude-dir=.git --exclude='*.bin' --exclude='*.hex' "$pattern" $roots 2>/dev/null || true)
  if [ -n "$matches" ]; then
    printf '%s\n' "$matches" >&2
    echo "persistence invariant forbidden pattern found: $description" >&2
    exit 1
  fi
}

require_file() {
  if [ ! -f "$1" ]; then
    echo "persistence invariant required file missing: $1" >&2
    exit 1
  fi
}

snapshot_file="crates/hydra-msg/src/persistence/snapshot.rs"
storage_file="crates/hydra-msg/src/api/storage.rs"
codec_storage_file="crates/hydra-msg/src/codec/storage.rs"
wasm_persistence_file="crates/hydra-msg/src/browser/persistence.rs"
wasm_persistence_js_file="crates/hydra-msg/src/browser/persistence_js.rs"
storage_tests_file="crates/hydra-msg/src/tests/storage.rs"
persistence_tests_file="crates/hydra-msg/src/tests/persistence.rs"
parser_vector_root="qa/vectors/persistence/parser-stress"
positive_vector_root="qa/vectors/persistence/positive"
negative_vector_root="qa/vectors/persistence/negative"
persistence_vector_root="qa/vectors/persistence"

require_file "$snapshot_file"
require_file "$storage_file"
require_file "$codec_storage_file"
require_file "$wasm_persistence_file"
require_file "$wasm_persistence_js_file"
require_file "$storage_tests_file"
require_file "$persistence_tests_file"
require_file "$parser_vector_root/manifest.sha3-256"
require_file "$positive_vector_root/manifest.sha3-256"
require_file "$negative_vector_root/manifest.sha3-256"
require_file "$persistence_vector_root/manifest.sha3-256"

require_source_text "$snapshot_file" "MAX_IDENTITIES" "snapshot collection-count guardrail"
require_source_text "$snapshot_file" "MAX_CONTACTS" "contact collection-count guardrail"
require_source_text "$snapshot_file" "MAX_MESSAGES" "message collection-count guardrail"
require_source_text "$snapshot_file" "MAX_LOBBIES" "lobby collection-count guardrail"
require_source_text "$snapshot_file" "MAX_ANONYMOUS_AUTH_SPENT" "anonymous-auth collection-count guardrail"
require_source_text "$snapshot_file" "HashSet" "duplicate collection record detection"
require_source_text "$snapshot_file" "reject_duplicate_collection_record" "duplicate collection record rejection helper"
require_source_text "$snapshot_file" "reject_collection_limit" "collection limit rejection helper"
require_source_text "$snapshot_file" "state record kind" "unknown snapshot record rejection"
require_source_text "$persistence_tests_file" "persistence_parser_stress_vectors_reject_malformed_containers" "parser-stress fixture regression test"
require_source_text "$persistence_tests_file" "state_snapshot_validation_rejects_duplicates_unknowns_and_collection_replays" "snapshot duplicate/unknown regression test"
require_source_text "$persistence_tests_file" "current_persistence_vectors_use_chunked_storage_and_round_trip" "current chunked persistence regression test"
require_source_text "$persistence_tests_file" "old_format_persistence_envelopes_fail_closed" "old-format persistence fail-closed regression test"
require_source_text "$persistence_tests_file" "frozen_persistence_stale_generation_and_restore_floor_vectors_hold" "stale-generation and restore-floor vector regression test"
require_source_text "$storage_file" "verify_backup(" "passworded backup verification facade retained"
require_source_text "$storage_file" "open_verified_backup_snapshot(bytes.as_ref(), password.as_ref())" "backup verification authenticates with supplied password"
require_source_text "$codec_storage_file" "reject_oversize_envelope" "encrypted envelope size limit retained"
require_source_text "$codec_storage_file" "reject_long_envelope_lines" "encrypted envelope line-length limit retained"
require_source_text "$wasm_persistence_js_file" "indexedDB" "WASM persistence uses IndexedDB"
require_source_text "$wasm_persistence_file" "opaque" "WASM persistence adapter documents opaque encrypted bytes"

forbidden_search "crates examples" 'localStorage[.\[]' "direct localStorage use for HYDRA state"
forbidden_search "crates examples" 'state\.(json|txt)|plaintext_state|HYDRA-MSG-STATE-V|STATE_V' "legacy plaintext or numbered state format resurrection"
forbidden_search "crates/hydra-msg-wasm examples docs/spec docs/impl docs/validation README.md" 'WasmHydra\.open(Default)?\s*\(' "durable-looking WASM no-op open path"
forbidden_search "crates docs/spec docs/impl docs/validation README.md" 'verify_backup\([^,)]*\)|verifyBackup\([^,)]*\)' "stale one-argument backup verification reference"
forbidden_search "crates/hydra-msg-wasm examples/mobile_perf_web" 'openDatabase|sql\.js|sqlite|localforage' "browser SQLite/WebSQL/localForage persistence detour"

parser_locations=$(grep -RInE 'fn parse_chunked_storage|fn state_snapshot_text' crates/hydra-msg/src --exclude-dir=target | cut -d: -f1 | sort -u | tr '\n' ' ')
case "$parser_locations" in
  *"crates/hydra-msg/src/codec/storage.rs"*"crates/hydra-msg/src/persistence/snapshot/helpers.rs"*) ;;
  *)
    echo "persistence invariant parser ownership mismatch: $parser_locations" >&2
    exit 1
    ;;
esac
unexpected_parsers=$(grep -RInE 'fn parse_chunked_storage|fn state_snapshot_text' crates/hydra-msg/src --exclude-dir=target | grep -Ev 'crates/hydra-msg/src/codec/storage.rs|crates/hydra-msg/src/persistence/snapshot/helpers.rs' || true)
if [ -n "$unexpected_parsers" ]; then
  printf '%s\n' "$unexpected_parsers" >&2
  echo "duplicate snapshot/envelope parser found outside canonical owners" >&2
  exit 1
fi

parser_vector_count=$(find "$parser_vector_root" -mindepth 2 -maxdepth 2 -name metadata.json | wc -l | tr -d ' ')
if [ "$parser_vector_count" -lt 5 ]; then
  echo "expected at least 5 persistence parser-stress vectors, found $parser_vector_count" >&2
  exit 1
fi
positive_vector_count=$(find "$positive_vector_root" -mindepth 2 -maxdepth 2 -name metadata.json | wc -l | tr -d ' ')
if [ "$positive_vector_count" -lt 2 ]; then
  echo "expected at least 2 positive persistence vectors, found $positive_vector_count" >&2
  exit 1
fi
negative_vector_count=$(find "$negative_vector_root" -mindepth 2 -maxdepth 2 -name metadata.json | wc -l | tr -d ' ')
if [ "$negative_vector_count" -lt 6 ]; then
  echo "expected at least 6 negative persistence vectors, found $negative_vector_count" >&2
  exit 1
fi

for vector_id in \
  TV-PERSISTENCE-STATE-BAD-MAGIC \
  TV-PERSISTENCE-STATE-EMPTY-CIPHERTEXT \
  TV-PERSISTENCE-BACKUP-BAD-KDF \
  TV-PERSISTENCE-BACKUP-BAD-NONCE \
  TV-PERSISTENCE-SNAPSHOT-DUPLICATE-SCALAR
 do
  require_file "$parser_vector_root/$vector_id/metadata.json"
  require_source_text "$parser_vector_root/$vector_id/metadata.json" '"expected_result":"reject"' "$vector_id expected rejection metadata"
 done

for vector_id in \
  TV-PERSIST-EMPTY-000 \
  TV-PERSIST-FULL-000
 do
  require_file "$positive_vector_root/$vector_id/metadata.json"
  require_source_text "$positive_vector_root/$vector_id/metadata.json" '"expected_result"' "$vector_id metadata present"
 done

for vector_id in \
  TV-PERSIST-WRONG-PASSWORD-000 \
  TV-PERSIST-BAD-KDF-PARAMS-000 \
  TV-PERSIST-CIPHERTEXT-FLIP-000 \
  TV-PERSIST-TRUNCATED-000 \
  TV-PERSIST-BAD-SNAPSHOT-000 \
  TV-PERSIST-STALE-GENERATION-000
 do
  require_file "$negative_vector_root/$vector_id/metadata.json"
  require_source_text "$negative_vector_root/$vector_id/metadata.json" '"expected_result":"reject"' "$vector_id expected rejection metadata"
 done

echo "persistence invariant checks passed"
