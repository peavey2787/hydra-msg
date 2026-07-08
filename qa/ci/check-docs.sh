#!/usr/bin/env sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository"

required_paths="docs/spec docs/impl docs/validation docs/project qa/ci qa/tools/vector-gen qa/vectors/candidate"
for path in $required_paths; do
  test -e "$path" || {
    echo "required path missing: $path" >&2
    exit 1
  }
done

if grep -RInE 'docs/planning' docs crates README.md Cargo.toml; then
  echo "stale docs/planning reference found" >&2
  exit 1
fi

if grep -RInE 'hydra-types|hydra-wire' docs crates README.md Cargo.toml; then
  echo "retired crate name reference found" >&2
  exit 1
fi

if grep -RInE 'Kyber|Dilithium|XChaCha20' docs/spec docs/impl docs/validation crates; then
  echo "deprecated primitive terminology found" >&2
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
