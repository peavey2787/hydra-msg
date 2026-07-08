#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/repo-root.sh"
hydra_enter_repo_root

required_paths="docs/spec docs/impl docs/validation docs/project qa/ci qa/tools/vector-gen qa/vectors/candidate"
for path in $required_paths; do
  test -e "$path" || {
    echo "required path missing: $path" >&2
    exit 1
  }
done

# Keep docs top-level clean: roadmap only.
for path in docs/*; do
  if [ -f "$path" ] && [ "$path" != "docs/roadmap.md" ]; then
    echo "unexpected top-level docs file: $path" >&2
    exit 1
  fi
done

# docs/project is for assistant working material. Product docs belong in spec/impl/validation.
if find docs/project -type f ! -path 'docs/project/audit/*' | grep .; then
  echo "non-audit file found under docs/project" >&2
  exit 1
fi

# Every nested README must offer a path back to the main README.
for readme in $(find . -name README.md -type f ! -path './.git/*' ! -path './target/*'); do
  if [ "$readme" = "./README.md" ]; then
    continue
  fi
  if ! grep -q "Main README" "$readme"; then
    echo "README missing Main README navigation: $readme" >&2
    exit 1
  fi
done

if grep -RInE 'docs/planning' docs crates README.md Cargo.toml; then
  echo "docs/planning reference found" >&2
  exit 1
fi

if grep -RInE 'docs/project/(message-flow|public-developer-api|benchmark-results|carrier-examples|hydra-msg-cli|wasm-javascript-bindings|production-qa-gate|release-readiness)' docs crates examples README.md Cargo.toml; then
  echo "product doc reference points into docs/project" >&2
  exit 1
fi

if grep -RInE 'hydra-types|hydra-wire' docs crates README.md Cargo.toml; then
  echo "crate name reference found" >&2
  exit 1
fi

if grep -RInE 'Kyber|Dilithium|XChaCha20' docs/spec docs/impl docs/validation crates; then
  echo "primitive terminology found" >&2
  exit 1
fi

if grep -RInE 'todo!|unimplemented!|TODO|FIXME' crates; then
  echo "source TODO/unimplemented marker found" >&2
  exit 1
fi

for script in qa/ci/*.sh; do
  if [ ! -s "$script" ]; then
    echo "empty QA script found: $script" >&2
    exit 1
  fi
done

echo "docs checks passed"
