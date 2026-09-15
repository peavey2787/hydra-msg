# HYDRA-MSG fuzzing workspace

This directory contains the deterministic fuzz-smoke gate and the nightly cargo-fuzz/libFuzzer harness. The top-level `check-all` runner always places fuzzing last.

## Navigation

- [Main README](../../README.md)
- [Parent workspace](../README.md)

## Campaign modes

The default local mode is deliberately bounded:

```bash
./qa/ci/check-all.sh --only fuzz
```

It runs 256 iterations for every cargo-fuzz target. The full default `check-all` run uses the same smoke budget.

Use a time-bounded overnight campaign explicitly:

```bash
./qa/ci/check-all.sh --only fuzz --overnight
```

Overnight mode runs each fast target for 15 minutes and the expensive stateful message-flow target for 5 minutes.

Use the deep campaign explicitly:

```bash
./qa/ci/check-all.sh --only fuzz --deep-fuzz
```

Deep mode runs 100,000 iterations for each fast target and 1,000 iterations for `message_stateful_flow`. Custom run counts remain available through `--fuzz-runs` and `--stateful-fuzz-runs`.

PowerShell equivalents are `-Only fuzz`, `-Overnight`, `-DeepFuzz`, `-FuzzRuns`, and `-StatefulFuzzRuns`.

## Fast and stateful message targets

`message_codec` is a fast, in-memory parser/encoder target. It does not create profiles, write temporary state, perform handshakes, or run cryptographic sessions. The hidden `hydra-msg/fuzzing` feature exposes only the internal codec hooks needed by this external harness.

`message_stateful_flow` separately exercises profile creation, identity/contact setup, handshake, message send/receive, attachment packaging, and tampered packet delivery. It intentionally receives a smaller budget in overnight and deep modes because every iteration performs expensive stateful cryptographic work.

## Direct gate

The direct gate always runs the deterministic `hydra-fuzz-gate`. Coverage-guided targets run only when `HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1` is set; `check-all` sets it automatically for its fuzz section.

```bash
./qa/ci/fuzz/check-fuzz.sh
```

For a quick executable/exit-code check without replacing the real CI campaign:

```bash
HYDRA_FUZZ_CASES=2 HYDRA_FUZZ_INPUT_LIMIT=1 cargo run --locked -p hydra-fuzz-gate --
```

`HYDRA_FUZZ_INPUT_LIMIT` selects inputs evenly across the generated corpus.
Normal bounded CI uses 12 samples from the full eight-round corpus; omitting the
variable executes the complete configured corpus for direct and release runs.

Install the required tooling with `scripts/setup-dev-env.*`, or manually:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

Evidence is written under `target/hydra-fuzz-evidence/`. See [Coverage-guided fuzzing](../../docs/validation/gates/coverage-guided-fuzzing.md).
