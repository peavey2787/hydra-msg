#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

skip_wasm=0
if [ "${1:-}" = "--skip-wasm" ]; then
  skip_wasm=1
fi

run_step() {
  name=$1
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

# Example scripts may lose +x after ZIP extraction. Repair permissions here too
# so check-examples.sh works when run directly, not only through check-all.sh.
run_step "Linux executable permissions" sh qa/ci/core/linux-permissions.sh

checked_manifests="
examples/attachment_roundtrip/Cargo.toml
examples/contact_card/Cargo.toml
examples/handshake_roundtrip/Cargo.toml
examples/hydra-app-core/Cargo.toml
examples/hydra-app/Cargo.toml
examples/lobby_roundtrip/Cargo.toml
examples/manual_file_carrier/Cargo.toml
examples/mobile_perf_web/Cargo.toml
examples/webrtc_manual_carrier/Cargo.toml
"

manifest_is_checked() {
  manifest=$1
  for checked in $checked_manifests; do
    if [ "$checked" = "$manifest" ]; then
      return 0
    fi
  done
  return 1
}

assert_all_example_manifests_covered() {
  while IFS= read -r manifest; do
    if ! manifest_is_checked "$manifest"; then
      echo "Example manifest is not covered by check-examples.sh: $manifest" >&2
      exit 1
    fi
  done <<EOF_FIND
$(find examples -mindepth 2 -maxdepth 2 -name Cargo.toml -print | sort)
EOF_FIND
}

assert_all_example_manifests_covered

run_web_host_step() {
  name=$1
  manifest=$2
  addr=$3
  url=$4
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to smoke-run long-running web host examples." >&2
    exit 1
  fi

  printf '\n==> %s\n' "$name"
  cargo run --manifest-path "$manifest" -- "$addr" &
  pid=$!
  cleanup() {
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  }
  trap cleanup INT TERM EXIT
  python3 - "$url" <<'PY'
import sys
import time
import urllib.request

url = sys.argv[1]
deadline = time.time() + 60
last_error = None
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            if response.status == 200:
                raise SystemExit(0)
            last_error = f"unexpected HTTP status {response.status}"
    except Exception as error:  # noqa: BLE001 - diagnostic-only CI smoke probe
        last_error = str(error)
        time.sleep(0.5)
raise SystemExit(f"web host did not respond at {url}: {last_error}")
PY
  cleanup
  trap - INT TERM EXIT
}

run_step "handshake_roundtrip example package" \
  cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
run_step "contact_card example package" \
  cargo run --manifest-path examples/contact_card/Cargo.toml
run_step "attachment_roundtrip example package" \
  cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
run_step "lobby_roundtrip example package" \
  cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
run_step "manual_file_carrier example package" \
  cargo run --manifest-path examples/manual_file_carrier/Cargo.toml

run_step "hydra-app-core package check" \
  cargo check --manifest-path examples/hydra-app-core/Cargo.toml --all-targets --all-features
run_step "hydra-app-core create_identity example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example create_identity
run_step "hydra-app-core start_session_send_receive example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --features test-support --example start_session_send_receive
run_step "hydra-app-core group_create_join example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example group_create_join
run_step "hydra-app-core identity_store example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example identity_store
run_step "hydra-app-core message_store example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example message_store
run_step "hydra-app-core transport_relay example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example transport_relay
run_step "hydra-app-core recovery_export_import example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example recovery_export_import
run_step "hydra-app-core device_linking example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example device_linking
run_step "hydra-app-core attachment_handling example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example attachment_handling
run_step "hydra-app-core abuse_failure_tests example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example abuse_failure_tests
run_step "hydra-app-core live_state_store example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --features test-support --example live_state_store
run_step "hydra-app-core signed_backup_history example" \
  cargo run --manifest-path examples/hydra-app-core/Cargo.toml --example signed_backup_history

run_step "hydra-app example package" \
  cargo run --manifest-path examples/hydra-app/Cargo.toml -- help

run_step "mobile_perf_web host compile" \
  cargo check --manifest-path examples/mobile_perf_web/Cargo.toml
run_step "webrtc_manual_carrier host compile" \
  cargo check --manifest-path examples/webrtc_manual_carrier/Cargo.toml
run_web_host_step "mobile_perf_web example package smoke run" \
  examples/mobile_perf_web/Cargo.toml 127.0.0.1:18788 http://127.0.0.1:18788/
run_web_host_step "webrtc_manual_carrier example package smoke run" \
  examples/webrtc_manual_carrier/Cargo.toml 127.0.0.1:18789 http://127.0.0.1:18789/

if [ "$skip_wasm" -eq 0 ]; then
  if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "wasm-pack is required for browser example packages." >&2
    echo "Install with: cargo install wasm-pack --locked" >&2
    echo "or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi

  run_step "mobile_perf_web WASM package" \
    examples/mobile_perf_web/scripts/build-wasm.sh
  run_step "webrtc_manual_carrier WASM package" \
    examples/webrtc_manual_carrier/scripts/build-wasm.sh
else
  echo "WASM browser package checks skipped by --skip-wasm."
fi

printf '\nHYDRA-MSG example checks passed.\n'
