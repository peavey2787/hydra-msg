# Coverage, complexity, CRAP, and mutation-testing audit

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

Status: implementation QA hardening artifact.

Green tests are necessary but not sufficient. HYDRA release validation also measures production coverage, cyclomatic complexity, CRAP, source ownership, and targeted mutation resistance. Static policy checks remain useful drift guards, but they do not substitute for executable behavioral evidence.

## Coverage report policy

The measured coverage section in the shared `qa/ci/run_all.py` orchestration runs the native `qa/ci/quality/check-coverage.*` implementation with `HYDRA_RUN_COVERAGE=1` on both Linux and Windows. Coverage uses nightly Rust because branch instrumentation is nightly-only. The gate creates:

```text
target/coverage/hydra.lcov
target/coverage/html/index.html
target/coverage/function-quality.tsv
```

The LCOV run executes the instrumented workspace once. The HTML report is generated afterward from the already-collected profiling data with `cargo llvm-cov report`; the test suite is not deliberately executed a second time just to render HTML.

Critical cryptographic functions require 100% line and branch coverage. Native production function ranges require at least 85% aggregate line coverage and 65% aggregate branch coverage. The native LCOV aggregate excludes only the `hydra-msg-cli` and `hydra-msg-wasm` adapter crates because their executable release evidence is collected by the interop and real-browser gates before coverage. Those adapters remain subject to the production CC limit.

`qa/coverage/critical-functions.tsv` is the canonical critical-function manifest. It identifies cryptographic primitives and security-critical key schedule, handshake, ratchet, and encrypted-storage functions that must remain fully exercised. A critical target that disappears from the production scan or has no LCOV executable-line data fails the gate instead of being silently skipped.

## Complexity and CRAP policy

Cyclomatic complexity is capped at 12 for production Rust functions under `crates/*/src`. `qa/ci/quality/check-complexity.*` enforces that limit even before measured coverage runs, so excessive control-flow complexity cannot hide behind high test coverage.

CRAP is capped at 25 for native production functions that execute in the coverage run. A native function with zero hits and CC >= 8 also fails the gate (except formatting-only `fmt` implementations), so aggregate coverage cannot hide a complex untested path. The measured gate uses the standard form:

```text
CRAP = CC^2 * (1 - coverage)^3 + CC
```

where `coverage` is the function's measured line-coverage fraction. The function-level report records source path, function name, line range, CC, line coverage, branch coverage, CRAP, and whether the function is critical.

## Source LOC ownership

Production/reference-app Rust source files normally have a maximum of 300 lines. `qa/ci/policy/check-rust-file-sizes.*` scans `crates/` and `examples/`. Test-only Rust modules are also capped at 300 lines by the cross-platform test-quality gate and are split rather than exempted. A larger canonical codec, static vocabulary/table, library owner, or facade may exist only through an explicit entry in `qa/ci/policy/rust-size-allowlist.txt` with a narrow maximum and ownership reason. Stale exceptions fail and should be removed when a file is split below the normal limit.

The LOC allow-list is not a complexity exception. Functions in an allow-listed file still must satisfy CC <= 12 and the applicable measured CRAP/coverage policy.

## Test-quality audit

`qa/ci/quality/check-test-quality.py` performs structural test checks. It rejects ignored tests, empty test bodies, obvious constant assertions such as `assert!(true)`, simple self-comparisons such as `assert_eq!(x, x)`, tests with no assertion/error evidence, and exact duplicate normalized Rust test bodies.

Generic `.is_err()` assertions are now fail-closed reviewed rather than merely inventoried. `qa/test-quality/generic-is-err-allowlist.tsv` names every intentionally broad fail-closed test and records a rationale; a new generic assertion that is not reviewed, a renamed/moved assertion, or a stale allow-list entry fails `check-test-quality.py`. The generated `target/test-quality/generic-is-err.txt` records the exact source location and rationale for release evidence. Security-critical handshake and KDF-tamper paths use exact error assertions plus state-preservation checks where state can advance.

Intentional overlap is retained when tests exercise distinct boundaries, modes, implementations, or state transitions. Exact duplicate execution in the orchestration layer is avoided where one earlier `cargo test --workspace --all-targets` run already supplied the same compile/test evidence.

## Coverage gaps

A static source review cannot truthfully certify that the measured thresholds are already met. The authoritative evidence is produced by the LCOV/CRAP gate on the exact candidate tree. Critical-function misses, native aggregate shortfalls, high-CRAP functions, and complex zero-hit native functions are listed in the failing output; per-function detail is written to `target/coverage/function-quality.tsv`, with HTML line/branch detail under `target/coverage/html/`.

The coverage gate is intentionally fail-closed for critical functions at 100% line and branch coverage. Native production function ranges are also aggregated across executable LCOV data and must remain at or above 85% line and 65% branch coverage. CRAP <= 25 applies to executed native functions, while the zero-hit/CC rule prevents a complex untested function from being diluted by aggregate coverage. CLI and WASM adapter coverage is not inferred from a native host LCOV run; their release evidence comes from the interop and Playwright gates.

## Mutation testing target

`qa/mutation/targets.tsv` is the canonical Mutation testing target manifest. The static gate fails if a listed source file, test file, or mutation-killing test disappears. Target classes include replay checks, compact-carrier bounds/domain separation, domain separation labels, generation rollback checks, signature verification, fragment reassembly, group membership/rekey rules, accepted-INIT idempotency, contact/purpose/identity/candidate competing-handshake selection, the pre-FINISH establishment gate, independent FINISH mode/counter validation, authenticated FINISH validation, high-volume hostile retransmission, downgrade rejection, weak-key rejection, and transcript-substitution rejection. The manifest paths are checked statically, so moved or renamed mutation-killing tests fail the gate instead of silently dropping mutation coverage.

Measured mutation testing runs only after the coverage section in `check-all`, so a candidate that has not first satisfied coverage, CC, and CRAP cannot proceed to mutation certification. Set `HYDRA_RUN_MUTATION=1` when invoking `qa/ci/quality/check-mutation.*` directly; the full release runner sets it for the mutation section.

The mutation runner uses a baseline-derived timeout by default because cryptographic and persistence tests can be slow. A resumed run may explicitly skip the baseline only after the exact same source tree already passed it. Surviving non-equivalent mutants in a listed security target block release.

Mutation testing complements coverage; it does not replace it. High coverage proves execution, while killed mutants provide evidence that assertions actually distinguish secure behavior from nearby faulty behavior.

## Release order

The normal release-quality order is:

```text
workspace tests / clippy / static security gates
        -> test-quality + CC + 300-LOC ownership
        -> real example/browser/memory-safety evidence
        -> LCOV + 85%/65% native aggregate + 100% critical + CRAP
        -> targeted mutation testing
        -> fuzzing
```

This ordering avoids spending mutation/fuzz time on a candidate with known compile, test, coverage, complexity, or CRAP failures.
