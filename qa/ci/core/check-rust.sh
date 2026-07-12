#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

# Rebuild the root lock graph from manifests so CI cannot fail on a stale checked-in lock.
rm -f Cargo.lock
cargo generate-lockfile
cargo fetch

# Validate that the workspace manifests are readable before running heavier checks.
cargo metadata --format-version 1 --no-deps >/dev/null

cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
