# Coverage / mutation-testing target audit

Status: implementation QA hardening artifact.

This audit makes the coverage and mutation-testing expectations explicit for production readiness. Green unit tests alone are not enough; HYDRA must track which critical protocol paths are exercised, which negative paths are covered, and which mutation classes must be killed before release certification.

## Coverage report policy

This section defines the required coverage report for release evidence.

The default local `check-all` gate performs a static coverage-manifest check so contributors do not need extra tooling for every edit. Release CI and release-candidate validation must additionally set `HYDRA_RUN_COVERAGE=1` when running `qa/ci/quality/check-coverage.*`. That mode uses `cargo llvm-cov` to create:

```text
 target/coverage/hydra.lcov
 target/coverage/html/index.html
```

The threshold helper then reads `qa/coverage/critical-paths.tsv` and enforces each critical-path coverage threshold against the LCOV report. The LCOV file is the release evidence; screenshots or prose summaries are not enough.

Rust branch coverage currently requires a nightly compiler because `cargo-llvm-cov --branch` enables the compiler's nightly-only coverage instrumentation. The coverage scripts therefore use `HYDRA_COVERAGE_TOOLCHAIN`, defaulting to `nightly`, and ensure `llvm-tools-preview` is installed for that same toolchain. Line and branch thresholds are not weakened to make stable-only coverage pass.

## Critical-path coverage threshold

`qa/coverage/critical-paths.tsv` is the canonical target list. Every row names:

```text
id | coverage class | minimum line coverage | minimum branch coverage | source file | test file | required test
```

The static gate fails if the source file, test file, or named test disappears. The measured coverage gate fails if the LCOV report drops below the row's line or branch threshold.

The matrix currently requires direct evidence for:

- parser/codec branch coverage;
- negative-path coverage;
- state-machine transition coverage;
- generation rollback checks;
- backup import atomicity;
- session replay and skipped-key transitions;
- signature verification rejection;
- fragment reassembly rejection;
- group membership and group rekey transitions.

## Parser/codec branch coverage

Parser and codec rows must include malformed or hostile inputs, not only round trips. The named rows cover oversized attachment declarations, malformed persistence containers, storage envelope parsing, and trailing-data rejection. A parser refactor is not complete until the manifest still points at a test that reaches reject branches before expensive allocation, decryption, signature verification, or state mutation.

## Negative-path coverage

Every security-critical accept path needs a paired reject path that proves failed validation leaves state unchanged. Required negative paths include replay, wrong signature, stale generation, malformed fragments, oversized inputs, bad inner binding, invalid group sender, and missing TreeKEM path. Tests that only assert `is_err()` are not enough for new critical paths; they should also assert generation, chain cursor, replay cache, or stored collection state did not advance when applicable.

## State-machine transition coverage

State-machine transition coverage must include:

- valid ordered transition;
- valid out-of-order transition where supported;
- replay rejection;
- authentication failure without state advancement;
- boundary transition at the maximum allowed gap/limit;
- transition rejection above the maximum allowed gap/limit;
- terminal/forked/closed-state rejection for group state.

The manifest intentionally tracks the test names that own these transitions so future cleanup cannot silently delete them.

## Mutation testing target

`qa/mutation/targets.tsv` is the canonical mutation target list. The static gate fails if a listed source file, test file, or mutation-killing test disappears. Release CI can set `HYDRA_RUN_MUTATION=1` to run `cargo-mutants` against the unique source files listed in that manifest and write mutation evidence under `target/mutants/`.

The measured gate deliberately does not impose a fixed timeout on the unmutated baseline. HYDRA's cryptographic, persistence, and crash-consistency tests can take several minutes, especially on laptops and under copied cargo-mutants worktrees. After the baseline succeeds, cargo-mutants applies a baseline-derived timeout to each mutant. The default is two times the measured baseline with a 120-second minimum. Maintainers may tune this without weakening the baseline check through `HYDRA_MUTATION_TIMEOUT_MULTIPLIER`, `HYDRA_MUTATION_MINIMUM_TEST_TIMEOUT`, and `HYDRA_MUTATION_JOBS`.

When the exact source tree has already passed the Rust test gate, a resumed Unix run may explicitly use `--skip-mutation-baseline`. That sets `HYDRA_MUTATION_BASELINE=skip` and applies `HYDRA_MUTATION_TIMEOUT` as a fixed per-mutant limit, defaulting to 1200 seconds. This is a resume optimization, not the normal standalone mutation policy.

The required mutation target classes are:

- replay checks;
- domain separation labels;
- generation rollback checks;
- signature verification;
- fragment reassembly;
- group membership/rekey rules.

Surviving mutants in any listed class block production release unless the maintainer documents why the mutant is equivalent and adds a narrower target or allowlist entry. Silent ignore is not allowed.

## CI placement

`qa/ci/core/check-tests.*` now runs the coverage and mutation target gates after interop and before cross-version/vector/static docs checks. `qa/ci/check-all.*` still runs fuzz last. Coverage and mutation are therefore visible in the normal gate while the heavier measured modes remain release-CI controlled.

## Current boundary

The static gates prove the manifests and required tests remain wired in. They do not by themselves prove a line/branch threshold or killed-mutant count. For an enterprise release candidate, the release log must include both:

```bash
HYDRA_RUN_COVERAGE=1 ./qa/ci/quality/check-coverage.sh
HYDRA_RUN_MUTATION=1 ./qa/ci/quality/check-mutation.sh
```

or the PowerShell equivalents on Windows.
