#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required metadata-leakage file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "metadata-leakage invariant missing from $file: $text" >&2
    exit 1
  fi
}

reject_text() {
  file=$1
  text=$2
  if grep -Fq -- "$text" "$file"; then
    echo "forbidden metadata-leakage claim found in $file: $text" >&2
    exit 1
  fi
}

audit=docs/validation/evidence/metadata-leakage-audit.md
threat=docs/spec/threat-model.md
release=docs/validation/release/release-criteria.md
qa_gate=docs/validation/gates/production-qa-gate.md
wasm=crates/hydra-msg-wasm/src/lib.rs
wasm_types=crates/hydra-msg-wasm/src/types.rs
wasm_persistence=crates/hydra-msg/src/browser/persistence.rs
wasm_docs=docs/impl/wasm-javascript-bindings.md
api_docs=docs/spec/public-developer-api.md
auth_docs=docs/spec/anonymous-auth.md
storage_codec=crates/hydra-msg/src/codec/storage.rs
status_file=crates/hydra-msg/src/persistence/status.rs
lobby_routing=crates/hydra-msg/src/lobby/routing.rs

for file in \
  "$audit" "$threat" "$release" "$qa_gate" "$wasm" "$wasm_types" "$wasm_persistence" \
  "$wasm_docs" "$api_docs" "$auth_docs" "$storage_codec" "$status_file" "$lobby_routing"
do
  require_file "$file"
done

for text in \
  "packet count" \
  "timing" \
  "routing" \
  "anonymous-auth" \
  "browser persistence" \
  "Backup metadata" \
  "not fully unlinkable" \
  "blind credentials" \
  "ZK nullifier" \
  "not metadata-free"
do
  require_text "$audit" "$text"
done

require_text "$wasm_types" "js_name = routingHint"
require_text "$wasm" "js_name = storageDebugStatus"
require_text "$wasm" "storage_status(&self) -> String"
require_text "$wasm_persistence" "revision: nextRevision"
require_text "$wasm_persistence" "adapterVersion: HYDRA_ADAPTER_VERSION"
require_text "$storage_codec" "STORAGE_CHUNK_PLAINTEXT_BYTES"
require_text "$storage_codec" "chunk_size"
require_text "$status_file" "HydraStorageDebugStatus"
require_text "$status_file" "must not log or expose this in production telemetry"
require_text "$lobby_routing" "routing_hint()"
require_text "$auth_docs" "not fully unlinkable"
require_text "$auth_docs" "bearer-token"
require_text "$auth_docs" "blind credentials"
require_text "$auth_docs" "ZK nullifier"
require_text "$threat" "metadata-leakage-audit.md"
require_text "$release" "metadata-leakage"
require_text "$qa_gate" "metadata-leakage"
require_text "$wasm_docs" "routingHint"
require_text "$api_docs" "routing_hint"

reject_text "$wasm_persistence" "updatedAtMs"
reject_text examples/mobile_perf_web/web/app.js "updatedAtMs"

if grep -RInE 'metadata-free|anonymous by default|only transport metadata|fully unlinkable anonymous auth|traffic-flow private' \
  docs README.md crates/hydra-msg-wasm/README.md --exclude-dir=target --exclude-dir=.git \
  | grep -v 'must not claim' | grep -v 'not metadata-free' | grep -v 'not anonymous by default'; then
  echo "forbidden metadata privacy overclaim found" >&2
  exit 1
fi

printf 'metadata-leakage checks passed.\n'
