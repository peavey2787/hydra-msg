#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required browser lifecycle file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "browser lifecycle invariant missing from $file: $text" >&2
    exit 1
  fi
}

reject_text() {
  file=$1
  text=$2
  if grep -Fq -- "$text" "$file"; then
    echo "forbidden browser lifecycle pattern found in $file: $text" >&2
    exit 1
  fi
}

wasm=crates/hydra-msg-wasm/src/lib.rs
adapter_facade=crates/hydra-msg/src/browser/persistence.rs
adapter_js=crates/hydra-msg/src/browser/persistence_js.rs

require_adapter_text() {
  text=$1
  if ! grep -Fq -- "$text" "$adapter_facade" "$adapter_js"; then
    echo "browser lifecycle invariant missing from browser persistence adapter: $text" >&2
    exit 1
  fi
}

reject_adapter_text() {
  text=$1
  if grep -Fq -- "$text" "$adapter_facade" "$adapter_js"; then
    echo "forbidden browser lifecycle pattern found in browser persistence adapter: $text" >&2
    exit 1
  fi
}
wasm_docs=crates/hydra-msg-wasm/README.md
impl_docs=docs/impl/wasm-javascript-bindings.md
api_docs=docs/spec/public-developer-api.md
app=examples/mobile_perf_web/web/app.js
host=examples/mobile_perf_web/src/main.rs
audit=docs/validation/evidence/wasm-browser-lifecycle-policy.md

for file in \
  "$wasm" \
  "$adapter_facade" \
  "$adapter_js" \
  "$wasm_docs" \
  "$impl_docs" \
  "$api_docs" \
  "$app" \
  "$host" \
  "$audit"
do
  require_file "$file"
done

require_adapter_text "const HYDRA_DB_VERSION = 2"
require_adapter_text "revision: nextRevision"
require_adapter_text "hydraIndexedDbSave(name, bytes, expectedRevision)"
require_adapter_text "currentRevision !== expectedRevision"
require_adapter_text "persistent record revision missing"
require_adapter_text "staleHydraProfileError"
require_adapter_text "last-writer-wins"
require_adapter_text "storage.persist"
require_adapter_text "hydraBrowserLifecycleStatus"
require_adapter_text "IndexedDB unavailable for HYDRA persistent state"

require_text "$wasm" "persistent_revision: Option<u64>"
require_text "$wasm" "js_name = persistentRevision"
require_text "$wasm" "js_name = browserLifecycleStatus"
require_text "$wasm" "js_name = requestPersistentStorage"
require_text "$wasm" "flush_browser_persistent"
require_text "$wasm" "open_browser_persistent"
require_adapter_text "save_encrypted_snapshot("

require_text "$app" "runMultiTabConcurrencyProbe"
require_text "$app" "browser-wasm-indexeddb-multi-tab-concurrency"
require_text "$app" "stale tab flush must be rejected instead of using last-writer-wins"
require_text "$app" "WasmHydra.browserLifecycleStatus"
require_text "$app" "WasmHydra.requestPersistentStorage"
require_text "$app" "const DB_VERSION = 2"
require_text "$host" 'data-action="multi-tab"'

for text in \
  "Private browsing" \
  "Storage eviction" \
  "QuotaExceededError" \
  "Multiple tabs" \
  "Tab crash during flush" \
  "Versioned DB format" \
  "Browser denying persistent storage" \
  "Mobile background"
do
  require_text "$audit" "$text"
done

require_text "$impl_docs" "compare-and-swap"
require_text "$impl_docs" "last-writer-wins"
require_text "$impl_docs" "browserLifecycleStatus"
require_text "$impl_docs" "requestPersistentStorage"
require_text "$api_docs" "profile-revision compare-and-swap"
require_text docs/spec/threat-model.md "wasm-browser-lifecycle-policy.md"

reject_adapter_text "localStorage."
reject_adapter_text "localStorage["
reject_adapter_text "updatedAtMs"
reject_text "$app" "updatedAtMs"
reject_text "$app" "last writer wins"

./qa/ci/reliability/check-browser-e2e.sh
printf 'WASM/browser lifecycle checks passed.\n'
