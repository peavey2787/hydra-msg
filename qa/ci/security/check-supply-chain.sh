#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
    echo "install with: cargo install $2 --locked" >&2
    echo "or run: ./scripts/setup-dev-env.sh" >&2
    exit 1
  fi
}

need_cmd cargo-audit cargo-audit
need_cmd cargo-deny cargo-deny

if [ ! -f deny.toml ]; then
  echo "missing deny.toml" >&2
  exit 1
fi

if [ ! -f LICENSE ]; then
  echo "missing LICENSE" >&2
  exit 1
fi

if grep -R 'license = "MIT OR Apache-2.0"' Cargo.toml crates examples qa --include Cargo.toml >/dev/null 2>&1; then
  echo "stale pre-freeze MIT OR Apache license string found in Cargo.toml files" >&2
  grep -R 'license = "MIT OR Apache-2.0"' Cargo.toml crates examples qa --include Cargo.toml >&2 || true
  exit 1
fi

if ! grep -q 'license = "GPL-2.0-or-later"' Cargo.toml; then
  echo "workspace license must be GPL-2.0-or-later" >&2
  exit 1
fi

printf '\n==> cargo-audit advisories\n'
cargo audit --deny warnings

printf '\n==> cargo-deny advisories/bans/licenses/sources\n'
cargo deny check advisories bans licenses sources

printf '\nHYDRA-MSG supply-chain checks passed.\n'
