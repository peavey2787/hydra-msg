#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required interop file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "interop invariant missing from $file: $text" >&2
    exit 1
  fi
}

for file in \
  qa/fixtures/interop/manifest.sha3-256 \
  qa/tests/interop/Cargo.toml \
  qa/tests/interop/src/lib.rs \
  qa/tests/interop/src/candidate_vectors.rs \
  crates/hydra-msg/src/packet_fragments/tests.rs \
  qa/fixtures/interop/browser/wasm-fixture-probe.js \
  docs/validation/evidence/interop-test-harness.md \
  examples/mobile_perf_web/web/app.js \
  examples/mobile_perf_web/src/main.rs
do
  require_file "$file"
done

python3 - <<'PY'
from pathlib import Path
import hashlib
manifest = Path('qa/fixtures/interop/manifest.sha3-256')
for line in manifest.read_text().splitlines():
    if not line.strip():
        continue
    expected, path = line.split(None, 1)
    actual = hashlib.sha3_256(Path(path).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f'interop fixture hash mismatch: {path}: expected {expected}, got {actual}')
PY

cargo test -p hydra-interop-tests

cli_dir=$(mktemp -d "${TMPDIR:-/tmp}/hydra-interop-cli.XXXXXX")
trap 'rm -rf "$cli_dir"' EXIT
cargo run -p hydra-msg-cli -- generate-id "$cli_dir" state-pw id-pw >/dev/null
cli_output=$(cargo run -p hydra-msg-cli -- doctor "$cli_dir" state-pw)
printf '%s\n' "$cli_output" | grep -Fq 'identities=1'
printf '%s\n' "$cli_output" | grep -Fq 'contacts=0'
printf '%s\n' "$cli_output" | grep -Fq 'messages=0'
printf '%s\n' "$cli_output" | grep -Fq 'lobbies=0'

require_text qa/tests/interop/src/lib.rs "frozen_protocol_packet_opens_in_current_session_runtime"
require_text qa/tests/interop/src/lib.rs "native_runtime_accepts_the_same_snapshot_bytes_wasm_persists"
require_text qa/tests/interop/src/lib.rs "pre_v1_and_future_fixture_contracts_fail_closed"
require_text qa/tests/interop/src/candidate_vectors.rs "candidate_negative_handshake_vectors_fail_closed"
require_text qa/tests/interop/src/candidate_vectors.rs "candidate_ratchet_vectors_execute_current_session_runtime"
require_text qa/tests/interop/src/candidate_vectors.rs "candidate_group_rejection_vectors_preserve_parent_state"
require_text crates/hydra-msg/src/packet_fragments/tests.rs "candidate_direct_fragment_vectors_decode_and_reassemble"
require_text crates/hydra-msg/src/packet_fragments/tests.rs "candidate_negative_fragment_vectors_fail_closed"
require_text examples/mobile_perf_web/web/app.js "runWasmInteropFixtureProbe"
require_text examples/mobile_perf_web/web/app.js "browser-wasm-frozen-fixture-interop"
require_text docs/validation/evidence/interop-test-harness.md "CLI ↔ WASM compatibility"

printf 'interop harness checks passed.\n'
