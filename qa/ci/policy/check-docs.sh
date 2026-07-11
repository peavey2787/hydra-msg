#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

required_paths="docs/spec docs/impl docs/validation qa/ci qa/evidence qa/fixtures/interop qa/tests qa/tools/vector-gen qa/vectors/candidate qa/vectors/cross-version"
for path in $required_paths; do
  test -e "$path" || {
    echo "required path missing: $path" >&2
    exit 1
  }
done

# Keep docs top-level grouped: product docs live under spec/impl/validation.
for path in docs/*; do
  if [ -f "$path" ]; then
    echo "unexpected top-level docs file: $path" >&2
    exit 1
  fi
done

# Long-lived release evidence belongs under qa/evidence, not docs/project.
if [ -d docs/project ] && find docs/project -type f | grep .; then
  echo "persistent file found under docs/project; move release evidence to qa/evidence" >&2
  exit 1
fi

navigation_block() {
  awk '
    /^## Navigation$/ { in_nav = 1; print; next }
    in_nav && /^## / { exit }
    in_nav { print }
  ' "$1"
}

require_nav_label() {
  file=$1
  nav=$2
  label=$3
  if ! printf '%s\n' "$nav" | grep -Fq "[$label]"; then
    echo "navigation missing $label: $file" >&2
    exit 1
  fi
}

forbidden_nav_label() {
  file=$1
  nav=$2
  label=$3
  if printf '%s\n' "$nav" | grep -Fq "[$label]"; then
    echo "navigation has wrong nav-family entry $label: $file" >&2
    exit 1
  fi
}

# The root README owns the public/project navigation only.
main_nav=$(navigation_block README.md)
for label in \
  "How HYDRA messaging works" \
  "Spec docs and repo structure" \
  "Crates" \
  "Examples" \
  "Public developer API" \
  "Benchmark notes"
do
  require_nav_label "README.md" "$main_nav" "$label"
done
for label in \
  "Roadmap" \
  "Protocol spec" \
  "Threat model" \
  "Security proof sketch" \
  "State machines" \
  "Envelope serialization" \
  "Chain-key evolution" \
  "TreeKEM profile" \
  "Group modes" \
  "Group rekey" \
  "Anonymous authorization"
do
  forbidden_nav_label "README.md" "$main_nav" "$label"
done

# Every nested README must offer a path back to the main README.
for readme in $(find . -name README.md -type f ! -path './.git/*' ! -path './target/*' ! -path '*/node_modules/*' ! -path '*/test-results/*' ! -path '*/playwright-report/*' ! -path './examples/*/web/pkg/*' ! -path 'examples/*/web/pkg/*'); do
  if [ "$readme" = "./README.md" ]; then
    continue
  fi
  if ! grep -q "Main README" "$readme"; then
    echo "README missing Main README navigation: $readme" >&2
    exit 1
  fi
done

is_main_nav_doc() {
  case "$1" in
    crates/*|examples/*|docs/impl/message-flow/README.md|docs/impl/carrier-examples.md|docs/impl/hydra-msg-cli.md|docs/impl/wasm-javascript-bindings.md|docs/spec/public-developer-api.md|docs/validation/benchmark-results.md)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_main_nav_family() {
  file=$1
  nav=$2
  for label in \
    "Main README" \
    "How HYDRA messaging works" \
    "Spec docs and repo structure" \
    "Crates" \
    "Examples" \
    "Public developer API" \
    "Benchmark notes"
  do
    require_nav_label "$file" "$nav" "$label"
  done

  for label in \
    "Roadmap" \
    "Spec document index" \
    "Protocol spec" \
    "Threat model" \
    "Security proof sketch" \
    "State machines" \
    "Envelope serialization" \
    "Chain-key evolution" \
    "TreeKEM profile" \
    "Group modes" \
    "Group rekey" \
    "Anonymous authorization"
  do
    forbidden_nav_label "$file" "$nav" "$label"
  done
}

require_spec_nav_family() {
  file=$1
  nav=$2
  for label in \
    "Main README" \
    "Spec document index" \
    "Protocol spec" \
    "Threat model" \
    "Security proof sketch" \
    "State machines" \
    "Envelope serialization" \
    "Chain-key evolution" \
    "TreeKEM profile" \
    "Group modes" \
    "Group rekey" \
    "Anonymous authorization"
  do
    require_nav_label "$file" "$nav" "$label"
  done

  for label in \
    "How HYDRA messaging works" \
    "Spec docs and repo structure" \
    "Crates" \
    "Examples" \
    "Public developer API" \
    "Benchmark notes" \
    "Carrier examples" \
    "Production QA gate" \
    "Roadmap"
  do
    forbidden_nav_label "$file" "$nav" "$label"
  done
}

# Main-nav docs are the root README nav entries and their children.
# Spec-nav docs are the spec index entries and their children. The spec index
# itself is the only root README entry that intentionally uses the spec family.
for doc in $(find crates examples docs/spec docs/impl docs/validation -name '*.md' -type f ! -path '*/node_modules/*' ! -path '*/test-results/*' ! -path '*/playwright-report/*' ! -path './examples/*/web/pkg/*' ! -path 'examples/*/web/pkg/*' | sort); do
  if ! grep -q '^## Navigation$' "$doc"; then
    echo "Markdown doc missing Navigation section: $doc" >&2
    exit 1
  fi

  doc_nav=$(navigation_block "$doc")
  if is_main_nav_doc "$doc"; then
    require_main_nav_family "$doc" "$doc_nav"
  else
    require_spec_nav_family "$doc" "$doc_nav"
  fi
done


if grep -RInE 'stupid[-]simple|stupid[ ]simple' README.md crates examples docs Cargo.toml; then
  echo "blocked simple-API wording found" >&2
  exit 1
fi

if grep -RInE 'docs/planning' docs crates README.md Cargo.toml; then
  echo "docs/planning reference found" >&2
  exit 1
fi

if grep -RIn 'docs/project/' docs crates examples README.md Cargo.toml; then
  echo "long-lived product or validation reference points into docs/project" >&2
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

find qa/ci -type f \( -name "*.sh" -o -name "*.ps1" \) | while IFS= read -r script; do
  if [ ! -s "$script" ]; then
    echo "empty QA script found: $script" >&2
    exit 1
  fi
done

qa/ci/policy/check-markdown-links.sh

echo "docs checks passed"
