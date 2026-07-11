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
examples/hydra-gui/hydra-app-core/Cargo.toml
examples/hydra-gui/hydra-app/Cargo.toml
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
$(find examples -mindepth 2 -name Cargo.toml -print | sort)
EOF_FIND
}

assert_all_example_manifests_covered

assert_reference_app_sdk_boundary() {
  if [ -e examples/hydra-app ] || [ -e examples/hydra-app-core ]; then
    echo "Old hydra-app example paths must not exist outside examples/hydra-gui." >&2
    exit 1
  fi
  if grep -RInE 'hydra-(core|crypto|group|session)|hydra_(core|crypto|group|session)' \
    examples/hydra-gui/hydra-app-core examples/hydra-gui/hydra-app; then
    echo "Reference app must depend only on the public hydra-msg SDK boundary." >&2
    exit 1
  fi
  if grep -RInE 'ContactTrustStore|IdentityVault|IdentityStore|IdentityUnlockSession|MessageStore|LiveStateStore|ChatShell|AppSession|AppGroup|RecoveryManifest|SignedBackup|TransportApi|DeviceRegistry' \
    examples/hydra-gui; then
    echo "Removed app-owned protocol/storage implementations must not return." >&2
    exit 1
  fi
  if grep -RInE '#\[allow\((dead_code|deprecated|unused|unused_imports|unused_must_use)' \
    examples/hydra-gui; then
    echo "Reference app must not suppress dead, deprecated, or unused-code diagnostics." >&2
    exit 1
  fi
}

assert_reference_app_sdk_boundary

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
  cargo check --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --all-targets --all-features
run_step "hydra-app-core reference tests" \
  cargo test --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --all-features
run_step "hydra-app-core identity and contacts example" \
  cargo run --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --example identity_contacts
run_step "hydra-app-core direct message example" \
  cargo run --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --example direct_message
run_step "hydra-app-core lobby and backup example" \
  cargo run --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml --example lobby_backup

run_step "hydra-app package check" \
  cargo check --manifest-path examples/hydra-gui/hydra-app/Cargo.toml --all-targets
run_step "hydra-app tests" \
  cargo test --manifest-path examples/hydra-gui/hydra-app/Cargo.toml
run_step "hydra-app command model" \
  cargo run --manifest-path examples/hydra-gui/hydra-app/Cargo.toml -- help

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
