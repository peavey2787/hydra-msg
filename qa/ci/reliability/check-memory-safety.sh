#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required memory-safety gate file missing: $1" >&2
    exit 1
  fi
}

require_text() {
  file=$1
  text=$2
  if ! grep -Fq -- "$text" "$file"; then
    echo "memory-safety invariant missing from $file: $text" >&2
    exit 1
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command missing: $1" >&2
    exit 1
  fi
}

run_cargo_test() {
  name=$1
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

policy=docs/validation/miri-sanitizer-fault-injection.md
crash_tests=crates/hydra-msg/src/tests/crash_consistency.rs
native_store=crates/hydra-msg/src/persistence/native_store.rs

for file in "$policy" "$crash_tests" "$native_store"; do
  require_file "$file"
done

for text in \
  "Miri" \
  "sanitizer" \
  "fault-injection" \
  "HYDRA_RUN_MIRI=1" \
  "HYDRA_RUN_SANITIZERS=1"
do
  require_text "$policy" "$text"
done

for stage in \
  "write temp file" \
  "sync temp file" \
  "rename/replace state" \
  "sync parent dir"
do
  require_text "$native_store" "test_failpoint(path, \"$stage\")?"
  require_text "$crash_tests" "$stage"
done

require_text "$native_store" "#[cfg(test)]"
require_text "$native_store" "set_test_failpoint"
require_text "$crash_tests" "backup_import_failure_is_atomic_in_memory_and_on_disk"
require_text "$crash_tests" "delete_identity_failure_restores_memory_and_disk"
require_text "$crash_tests" "delete_contact_failure_restores_memory_and_disk"
require_text "$crash_tests" "delete_message_failure_restores_memory_and_disk"

require_command cargo
run_cargo_test "fault-injection crash-consistency tests" \
  cargo test -p hydra-msg --lib tests::crash_consistency

if [ "${HYDRA_RUN_MIRI:-0}" = "1" ]; then
  require_command rustup
  require_command cargo
  if ! cargo +nightly miri --version >/dev/null 2>&1; then
    echo "cargo +nightly miri is unavailable. Install nightly and Miri first:" >&2
    echo "  rustup toolchain install nightly" >&2
    echo "  rustup +nightly component add miri" >&2
    exit 1
  fi
  : "${MIRIFLAGS:=-Zmiri-disable-isolation}"
  export MIRIFLAGS
  packages=${HYDRA_MIRI_PACKAGES:-"hydra-core hydra-envelope hydra-session"}
  for package in $packages; do
    run_cargo_test "Miri: $package" cargo +nightly miri test -p "$package"
  done
else
  printf '\nMiri execution skipped. Set HYDRA_RUN_MIRI=1 for the nightly Miri gate.\n'
fi

if [ "${HYDRA_RUN_SANITIZERS:-0}" = "1" ]; then
  require_command rustup
  require_command cargo
  if ! cargo +nightly -Z help >/dev/null 2>&1; then
    echo "cargo +nightly is unavailable. Install nightly first:" >&2
    echo "  rustup toolchain install nightly" >&2
    exit 1
  fi
  sanitizer=${HYDRA_SANITIZER:-address}
  target=${HYDRA_SANITIZER_TARGET:-x86_64-unknown-linux-gnu}
  packages=${HYDRA_SANITIZER_PACKAGES:-"hydra-core hydra-envelope hydra-session hydra-msg"}
  export RUSTFLAGS="-Zsanitizer=$sanitizer ${RUSTFLAGS:-}"
  for package in $packages; do
    run_cargo_test "sanitizer($sanitizer): $package" \
      cargo +nightly test -Zbuild-std --target "$target" -p "$package"
  done
else
  printf '\nSanitizer execution skipped. Set HYDRA_RUN_SANITIZERS=1 for the nightly sanitizer gate.\n'
fi

printf '\nMiri/sanitizer/fault-injection gate passed.\n'
