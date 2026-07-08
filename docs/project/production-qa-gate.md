# Production QA Gate

Status: P13 validation gate definition.

This document defines the validation gate that must pass before HYDRA-MSG moves
from production app hardening to release-candidate packaging.

P13 does not add product features. It turns the existing local validation flow
into a single repeatable gate for formatting, tests, linting, docs checks, and
vector checks.

## Required command

On Windows PowerShell, run:

```powershell
.\qa\ci\check-all.ps1 -SkipGui
```

To run the same gate and then launch the local GUI afterward:

```powershell
.\qa\ci\check-all.ps1
```

To format first and then check:

```powershell
.\qa\ci\check-all.ps1 -FixFormat -SkipGui
```

On Unix-like shells, run:

```sh
qa/ci/check-all.sh
```

## Gate contents

The production QA gate runs:

```text
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
docs/path/stale-term checks
qa/tools/vector-gen formatting/tests/clippy/manifest verification
```

The PowerShell runner can optionally launch:

```text
cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui
```

## Docs and stale-term checks

The docs checks verify that required authority directories exist and reject:

- stale references to the old planning-docs path;
- retired M1 crate-name references;
- deprecated primitive names in authoritative docs or source;
- source `todo!`, `unimplemented!`, `TODO`, or `FIXME` markers;
- empty QA scripts.

The checks intentionally avoid treating the existence of QA scripts as proof that
validation passed. Passing evidence is the command output from running the gate.

## Boundary invariant expectation

P13 inherits the roadmap boundary invariant rule. A milestone is not production
ready if its constants, counters, windows, timeouts, storage versions, retry
limits, or rejection thresholds lack boundary tests or documented behavior.

## Release-candidate rule

P14 must not begin until this gate passes locally on the active repo state.

Passing P13 means the production app validation gate is clean. It does not mean
HYDRA-MSG has reached final cryptographic release freeze; that remains governed
by `docs/validation/release-criteria.md`.


The PowerShell QA gate formats root and vector-generator Rust sources by default. Use `-CheckFormatOnly` when a non-mutating format check is required. The shell vector check accepts `--check-format` for the same strict behavior.
