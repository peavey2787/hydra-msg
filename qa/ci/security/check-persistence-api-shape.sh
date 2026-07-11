#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

wasm_file="crates/hydra-msg-wasm/src/lib.rs"
wasm_docs="crates/hydra-msg-wasm/README.md docs/impl/wasm-javascript-bindings.md docs/spec/public-developer-api.md"
product_roots="crates/hydra-msg-wasm examples docs/spec docs/impl docs/validation README.md"

require_source_text() {
  file=$1
  text=$2
  description=$3
  if ! grep -Fq "$text" "$file"; then
    echo "persistence API shape missing: $description" >&2
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
    echo "persistence API shape forbidden pattern found: $description" >&2
    echo "forbidden text: $text" >&2
    echo "file: $file" >&2
    exit 1
  fi
}

if [ ! -f "$wasm_file" ]; then
  echo "missing WASM binding file: $wasm_file" >&2
  exit 1
fi

require_source_text "$wasm_file" "js_name = openPersistent" "explicit async durable browser open"
require_source_text "$wasm_file" "pub async fn open_persistent" "async persistent open implementation"
require_source_text "$wasm_file" "js_name = openEphemeral" "explicit in-memory browser open"
require_source_text "$wasm_file" "pub fn open_ephemeral" "sync ephemeral open implementation"
require_source_text "$wasm_file" "js_name = flush" "explicit durable browser commit API"
require_source_text "$wasm_file" "pub async fn flush" "async flush implementation"
require_source_text "$wasm_file" "js_name = deletePersistent" "explicit persistent reset API"
require_source_text "$wasm_file" "js_name = verifyBackup" "passworded backup verification binding"
require_source_text "$wasm_file" "verify_backup(bytes, password)" "WASM backup verification authenticates with password"
require_source_text "$wasm_file" "dirty: bool" "explicit dirty-state tracking"
require_source_text "$wasm_file" "self.mark_dirty();" "mutating calls mark dirty instead of pretending synchronous IndexedDB durability"

forbidden_source_text "$wasm_file" "js_name = openDefault" "durable-looking WASM default open alias"
forbidden_source_text "$wasm_file" "pub fn open_default" "durable-looking WASM default open implementation"
forbidden_source_text "$wasm_file" "js_name = open)]" "ambiguous WASM open alias"

require_source_text "$wasm_file" "js_name = setPacketSize" "simple WASM packet sizing control"
forbidden_source_text "$wasm_file" "js_name = setMinEnvelopeSize" "removed WASM min envelope sizing control"
forbidden_source_text "$wasm_file" "js_name = setMaxEnvelopeSize" "removed WASM max envelope sizing control"
forbidden_source_text "$wasm_file" "js_name = maxEnvelopeSize" "extra WASM envelope sizing getter"
forbidden_source_text "$wasm_file" "js_name = effectiveMaxEnvelopeSize" "extra WASM effective envelope getter"
forbidden_source_text "$wasm_file" "js_name = minSupportedMaxEnvelopeSize" "extra WASM envelope lower-bound getter"
forbidden_source_text "$wasm_file" "js_name = protocolMaxEnvelopeSize" "extra WASM protocol max getter"
forbidden_source_text "$wasm_file" "js_name = sendEnvelopes" "extra WASM batch send API"
forbidden_source_text "$wasm_file" "js_name = sendTextEnvelopes" "extra WASM batch text send API"
forbidden_source_text "$wasm_file" "js_name = receiveEnvelopes" "extra WASM batch receive API"
forbidden_source_text "$wasm_file" "js_name = sendLobbyEnvelopes" "extra WASM lobby batch send API"
forbidden_source_text "$wasm_file" "js_name = receiveLobbyEnvelopes" "extra WASM lobby batch receive API"

forbidden_source_text "$wasm_file" "js_name = sendTo" "extra WASM transport callback send API"
forbidden_source_text "$wasm_file" "js_name = sendTextTo" "extra WASM transport callback text send API"
forbidden_source_text "$wasm_file" "js_name = receiveNext" "extra WASM incremental receive API"
forbidden_source_text "$wasm_file" "js_name = receiveLobbyNext" "extra WASM incremental lobby receive API"

if grep -RInE 'send_envelopes|receive_envelopes|send_lobby_envelopes|receive_lobby_envelopes|sendEnvelopes|sendTextEnvelopes|receiveEnvelopes|sendLobbyEnvelopes|receiveLobbyEnvelopes|send_to\(|receive_next\(|send_lobby_to\(|receive_lobby_next\(|sendTo|sendTextTo|receiveNext|receiveLobbyNext|minSupportedMaxEnvelopeSize|protocolMaxEnvelopeSize|effectiveMaxEnvelopeSize|maxEnvelopeSize|setMinEnvelopeSize|setMaxEnvelopeSize|set_min_envelope_size|set_max_envelope_size|send_batch|sendBatch|send_packets|sendPackets|setMinEnvelopeSize|setMaxEnvelopeSize' crates docs/spec docs/impl docs/validation README.md --exclude-dir=target --exclude-dir=.git; then
  echo "overexposed envelope sizing, batching, or packet-fragment API reference found" >&2
  exit 1
fi

if grep -RInE 'WasmHydra\.open(Default)?\s*\(' $product_roots --exclude-dir=target --exclude-dir=.git; then
  echo "durable-looking WASM open/openDefault reference found in product source/docs" >&2
  exit 1
fi

for doc in $wasm_docs; do
  require_source_text "$doc" "openPersistent" "persistent WASM API documentation"
  require_source_text "$doc" "openEphemeral" "ephemeral WASM API documentation"
  require_source_text "$doc" "flush" "explicit WASM flush documentation"
  require_source_text "$doc" "no ambiguous" "documentation calls out removed ambiguous WASM open aliases"
done

if grep -RInE 'verify_backup\([^,)]*\)|verifyBackup\([^,)]*\)' crates docs/spec docs/impl docs/validation README.md --exclude-dir=target --exclude-dir=.git; then
  echo "stale one-argument backup verification reference found" >&2
  exit 1
fi

if grep -RInE 'open_with_encrypted_state_snapshot|flush_encrypted_state_snapshot' README.md docs/spec docs/impl docs/validation crates/hydra-msg-wasm/README.md --exclude-dir=target --exclude-dir=.git; then
  echo "hidden encrypted snapshot hooks leaked into public docs" >&2
  exit 1
fi

if grep -RInF '#[doc(hidden)]' crates/hydra-msg/src --exclude-dir=target --exclude-dir=.git; then
  echo "doc-hidden APIs are forbidden in the hydra-msg v1 facade" >&2
  exit 1
fi

echo "persistence API shape checks passed"
