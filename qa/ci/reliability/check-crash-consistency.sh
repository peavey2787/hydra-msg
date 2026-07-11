#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required crash-consistency file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "crash-consistency invariant missing from $file: $text" >&2
    exit 1
  fi
}

native_store=crates/hydra-msg/src/persistence/native_store.rs
storage=crates/hydra-msg/src/api/storage.rs
identity=crates/hydra-msg/src/api/identity.rs
contacts=crates/hydra-msg/src/api/contacts.rs
messages=crates/hydra-msg/src/messages/mod.rs
crash_tests=crates/hydra-msg/src/tests/crash_consistency.rs
wasm_app=examples/mobile_perf_web/web/app.js
wasm_host=examples/mobile_perf_web/src/main.rs
audit=qa/evidence/crash-consistency-matrix.md

for file in \
  "$native_store" \
  "$storage" \
  "$identity" \
  "$contacts" \
  "$messages" \
  "$crash_tests" \
  "$wasm_app" \
  "$wasm_host" \
  "$audit"
do
  require_file "$file"
done

for stage in \
  'write temp file' \
  'sync temp file' \
  'rename/replace state' \
  'sync parent dir'
do
  require_text "$native_store" "test_failpoint(path, \"$stage\")?"
  require_text "$crash_tests" "$stage"
done

require_text "$native_store" "set_test_failpoint"
require_text "$storage" "restore_verified_backup_snapshot"
require_text "$storage" "self.apply_state_snapshot(&previous_snapshot)?"
require_text "$identity" "self.apply_state_snapshot(&previous_snapshot)"
require_text "$contacts" "self.apply_state_snapshot(&previous_snapshot)"
require_text "$messages" "self.apply_state_snapshot(&previous_snapshot)"
require_text "$crash_tests" "crash_before_state_rename_leaves_old_state_authoritative"
require_text "$crash_tests" "crash_temp_file_is_ignored_and_removed_on_next_successful_write"
require_text "$crash_tests" "renamed_state_before_parent_sync_or_rollback_is_openable_and_repairs_guard"
require_text "$crash_tests" "parent_dir_sync_failure_returns_error_but_leaves_openable_state"
require_text "$crash_tests" "rollback_evidence_write_failure_leaves_state_openable_and_repairable"
require_text "$crash_tests" "backup_import_failure_is_atomic_in_memory_and_on_disk"
require_text "$crash_tests" "delete_identity_failure_restores_memory_and_disk"
require_text "$crash_tests" "delete_contact_failure_restores_memory_and_disk"
require_text "$crash_tests" "delete_message_failure_restores_memory_and_disk"

require_text "$wasm_app" "runCrashConsistencyProbe"
require_text "$wasm_app" "browser-wasm-indexeddb-crash-consistency-matrix"
require_text "$wasm_app" "IndexedDB flush durability is tested by aborting the write transaction"
require_text "$wasm_app" "IndexedDB quota error handling is tested"
require_text "$wasm_app" "browser tab close mid-flush"
require_text "$wasm_app" "QuotaExceededError"
require_text "$wasm_app" "tx.abort()"
require_text "$wasm_host" 'data-action="crash-consistency"'
require_text docs/spec/threat-model.md "crash-consistency-matrix.md"

printf 'crash-consistency matrix checks passed.\n'
