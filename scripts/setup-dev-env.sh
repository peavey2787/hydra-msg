#!/usr/bin/env sh
set -eu

cat <<'EOF'

██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗
██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

        ASIC-grade dev environment bootstrap
EOF

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    echo "Install Rust with rustup first if cargo/rustup is missing: https://rustup.rs/" >&2
    exit 1
  fi
}

install_crate() {
  crate=$1
  binary=${2:-$1}
  if cargo install --list | grep -Eq "^${crate} v"; then
    echo "✓ $crate already installed"
  else
    echo "==> installing $crate"
    cargo install "$crate" --locked
  fi
  if [ -n "$binary" ]; then
    echo "✓ installed crate: $crate"
  fi
}

require_cmd rustup
require_cmd cargo

printf '\n==> Rust stable components\n'
rustup component add rustfmt clippy
rustup target add wasm32-unknown-unknown

printf '\n==> Rust nightly components for Miri/sanitizer/branch-coverage/fuzz gates\n'
if [ "${HYDRA_SKIP_NIGHTLY:-0}" = "1" ]; then
  echo "Skipping nightly setup because HYDRA_SKIP_NIGHTLY=1"
else
  rustup toolchain install nightly
  rustup +nightly component add miri rust-src llvm-tools-preview
fi

printf '\n==> Cargo QA tools\n'
install_crate cargo-audit cargo-audit
install_crate cargo-deny cargo-deny
install_crate wasm-pack wasm-pack
install_crate cargo-llvm-cov cargo-llvm-cov
install_crate cargo-mutants cargo-mutants
install_crate cargo-fuzz cargo-fuzz

printf '\n==> Host tool reminders\n'
if command -v node >/dev/null 2>&1; then
  echo "✓ node found: $(node --version)"
else
  echo "! node is not installed. Browser/example checks use node --check. Install Node.js 20+ or newer."
fi
if command -v npm >/dev/null 2>&1; then
  echo "✓ npm found: $(npm --version)"
  if [ "${HYDRA_SKIP_PLAYWRIGHT:-0}" = "1" ]; then
    echo "Skipping Playwright install because HYDRA_SKIP_PLAYWRIGHT=1"
  else
    echo "==> installing Playwright browser test dependencies and browser binaries"
    (
      cd qa/browser/playwright
      npm ci
      npm run install:browsers
    )
  fi
else
  echo "! npm is not installed. Real-browser Playwright evidence requires npm."
fi
if command -v python3 >/dev/null 2>&1; then
  echo "✓ python3 found: $(python3 --version 2>&1)"
else
  echo "! python3 is not installed. Release SBOM generation, interop fixture checks, and web-host smoke tests require python3."
fi
if command -v gpg >/dev/null 2>&1; then
  echo "✓ gpg found: $(gpg --version | head -n 1)"
else
  echo "! gpg is not installed. Release signing requires gpg for signed tags and checksum signatures."
fi
if command -v sha256sum >/dev/null 2>&1; then
  echo "✓ sha256sum found"
else
  echo "! sha256sum is not installed. Release hash publication requires sha256sum."
fi

cat <<'EOF'

HYDRA dev environment setup complete.

Suggested first validation run:
  ./qa/ci/core/linux-permissions.sh
  cargo fmt --check
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  ./qa/ci/check-all.sh

Optional release-candidate evidence:
  HYDRA_RUN_COVERAGE=1 ./qa/ci/quality/check-coverage.sh
  HYDRA_RUN_MUTATION=1 ./qa/ci/quality/check-mutation.sh
  HYDRA_RUN_MIRI=1 ./qa/ci/reliability/check-memory-safety.sh
  HYDRA_RUN_SANITIZERS=1 ./qa/ci/reliability/check-memory-safety.sh
  HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1 ./qa/ci/fuzz/check-fuzz.sh
  HYDRA_RUN_BROWSER_E2E=1 ./qa/ci/reliability/check-browser-e2e.sh

Release package/signing helpers:
  scripts/release/create-signed-tag.sh v0.1.0
  scripts/release/create-release-package.sh v0.1.0
  scripts/release/sign-release-artifacts.sh v0.1.0
  scripts/release/verify-release-artifacts.sh v0.1.0
EOF
