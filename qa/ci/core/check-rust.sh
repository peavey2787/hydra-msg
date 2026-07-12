#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

# Validate the committed lockfile before running heavier checks. Local and release
# CI must not rewrite Cargo.lock; stale locks are real failures there. Normal
# bounded GitHub CI may refresh the lock graph ephemerally because its purpose is
# fast commit validation, not release lock certification.
if [ "${HYDRA_CI_EPHEMERAL_LOCK_REFRESH:-0}" = "1" ]; then
  cargo metadata --format-version 1 --no-deps >/dev/null
else
  cargo metadata --locked --format-version 1 --no-deps >/dev/null
fi

cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
