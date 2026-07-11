#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

app_js="examples/mobile_perf_web/web/app.js"
server_rs="examples/mobile_perf_web/src/main.rs"

require_source_text() {
  file=$1
  text=$2
  description=$3
  if ! grep -Fq "$text" "$file"; then
    echo "mobile perf web check missing: $description" >&2
    echo "expected text: $text" >&2
    echo "file: $file" >&2
    exit 1
  fi
}

forbidden_source_text() {
  file=$1
  text=$2
  description=$3
  if grep -Fq "$text" "$file"; then
    echo "mobile perf web check found forbidden text: $description" >&2
    echo "forbidden text: $text" >&2
    echo "file: $file" >&2
    exit 1
  fi
}

[ -f "$app_js" ] || { echo "missing browser benchmark app: $app_js" >&2; exit 1; }
[ -f "$server_rs" ] || { echo "missing mobile perf host: $server_rs" >&2; exit 1; }

require_source_text "$server_rs" 'src="/app.js"' "external browser benchmark script"
require_source_text "$server_rs" 'include_str!("../web/app.js")' "host serves the browser benchmark script"
require_source_text "$server_rs" '/pkg-health' "WASM package health endpoint"
require_source_text "$server_rs" 'env!("CARGO_MANIFEST_DIR")' "runtime-independent WASM pkg path"
require_source_text "$server_rs" 'data-action="multi-tab"' "multi-tab concurrency button"

require_source_text "$app_js" 'ensureWasmPackageAvailable' "WASM package preflight check"
require_source_text "$app_js" 'WASM_JS_PATH' "centralized WASM JS path"
require_source_text "$app_js" 'WASM_BG_PATH' "centralized WASM binary path"
require_source_text "$app_js" 'openEphemeral(EPHEMERAL_PROFILE, STATE_PASSWORD)' "passworded ephemeral benchmark open"
require_source_text "$app_js" 'openPersistent(PERSISTENT_PROFILE, STATE_PASSWORD)' "passworded persistent benchmark open"
require_source_text "$app_js" 'openPersistent(RESTORE_PROFILE, STATE_PASSWORD)' "passworded restore-profile open"
require_source_text "$app_js" 'openEphemeral(`${EPHEMERAL_PROFILE}-persistence-peer-' "separate ephemeral peer for persistent send/receive validation"
require_source_text "$app_js" 'peer.replyHandshake(offer)' "two-instance persistent-suite handshake"
require_source_text "$app_js" 'received = peer.receive(packet) || received;' "persistent suite receives with peer session"
require_source_text "$app_js" 'await hydra.flush()' "explicit dirty-state flush in persistence suite"
require_source_text "$app_js" 'exportBackup(BACKUP_PASSWORD)' "backup export benchmark coverage"
require_source_text "$app_js" 'verifyBackup(backup, BACKUP_PASSWORD)' "passworded backup verification benchmark coverage"
require_source_text "$app_js" 'importBackup(backup, BACKUP_PASSWORD)' "backup import benchmark coverage"
require_source_text "$app_js" 'importBackup must mark restored persistent state dirty until explicit flush' "backup restore dirty-state boundary coverage"
require_source_text "$app_js" 'navigator.storage.estimate' "quota estimate probe"
require_source_text "$app_js" 'QuotaExceededError' "user-facing quota error path"
require_source_text "$app_js" 'runApiMisuseGuard' "browser misuse regression coverage"
require_source_text "$app_js" 'runMultiTabConcurrencyProbe' "multi-tab stale-writer regression coverage"
require_source_text "$app_js" 'browser-wasm-indexeddb-multi-tab-concurrency' "multi-tab CAS result payload"
require_source_text "$app_js" 'stale tab flush must be rejected instead of using last-writer-wins' "multi-tab stale flush rejection"
require_source_text "$app_js" 'WasmHydra.browserLifecycleStatus' "browser lifecycle status probe"
require_source_text "$app_js" 'WasmHydra.requestPersistentStorage' "persistent storage request probe"
require_source_text "$app_js" 'IndexedDB stores opaque encrypted HYDRA snapshot bytes' "opaque-byte storage note"

forbidden_source_text "$app_js" 'localStorage.' "HYDRA state must not read/write localStorage"
forbidden_source_text "$app_js" 'localStorage[' "HYDRA state must not read/write localStorage"
forbidden_source_text "$app_js" 'openDefault' "removed durable-looking WASM alias"
forbidden_source_text "$app_js" 'WasmHydra.open(' "ambiguous WASM open alias"

if grep -nE 'openPersistent\([^,\n\)]*\)' "$app_js"; then
  echo "mobile perf web check found openPersistent call without password argument" >&2
  exit 1
fi

if grep -nE 'openEphemeral\([^,\n\)]*\)' "$app_js"; then
  echo "mobile perf web check found openEphemeral call without password argument" >&2
  exit 1
fi

echo "mobile perf web checks passed"
