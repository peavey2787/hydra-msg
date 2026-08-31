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

run_step "shared example static policy" python3 qa/ci/core/check_examples_policy.py

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

if [ "${HYDRA_WORKSPACE_TESTS_ALREADY_RAN:-0}" = 1 ]; then
  echo "Workspace --all-targets tests already compiled/tested example targets; skipping duplicate compile/test-only example invocations."
else
  run_step "HYDRA GUI host compile" \
    cargo check --manifest-path examples/hydra-gui/Cargo.toml --all-targets
  run_step "HYDRA GUI tests" \
    cargo test --manifest-path examples/hydra-gui/Cargo.toml

  run_step "mobile_perf_web host compile" \
    cargo check --manifest-path examples/mobile_perf_web/Cargo.toml
  run_step "webrtc_manual_carrier host compile" \
    cargo check --manifest-path examples/webrtc_manual_carrier/Cargo.toml
  run_step "stego_lan_chat host compile" \
    cargo check --manifest-path examples/stego_lan_chat/Cargo.toml
fi
run_web_host_step "mobile_perf_web example package smoke run" \
  examples/mobile_perf_web/Cargo.toml 127.0.0.1:18788 http://127.0.0.1:18788/
run_web_host_step "webrtc_manual_carrier example package smoke run" \
  examples/webrtc_manual_carrier/Cargo.toml 127.0.0.1:18789 http://127.0.0.1:18789/
run_web_host_step "stego_lan_chat example package smoke run" \
  examples/stego_lan_chat/Cargo.toml 127.0.0.1:18790 http://127.0.0.1:18790/
run_web_host_step "HYDRA GUI example package smoke run" \
  examples/hydra-gui/Cargo.toml 127.0.0.1:18791 http://127.0.0.1:18791/

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
  run_step "stego_lan_chat WASM package" \
    examples/stego_lan_chat/scripts/build-wasm.sh
  run_step "HYDRA GUI WASM package" \
    examples/hydra-gui/scripts/build-wasm.sh
else
  echo "WASM browser package checks skipped by --skip-wasm."
fi

printf '\nHYDRA-MSG example checks passed.\n'
