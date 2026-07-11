# HYDRA-MSG fuzzing workspace

This directory contains deterministic fuzz-smoke infrastructure plus the release coverage-guided libFuzzer harness for parser, codec, and state-transition inputs. The full `check-all` gate runs fuzzing last and uses the long coverage-guided campaign by default.

## Navigation

- [Main README](../../README.md)
- [Parent workspace](../README.md)

## Gate

The direct fuzz gate is bounded and reproducible unless `HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1` is set. The top-level `check-all` sets that variable and runs this script last with an overnight release budget.

Unix:

```bash
./qa/ci/fuzz/check-fuzz.sh
```

PowerShell:

```powershell
.\qa\ci\fuzz\check-fuzz.ps1
```

The top-level `check-all` calls this script automatically as the final gate.

## Coverage scope

`hydra-fuzz-gate` exercises:

- HYDRA envelope header and protected-record decoders;
- encrypted local-state and backup parser entrypoints;
- contact, identity, handshake, lobby invite, anonymous-auth, message, and lobby receive parser boundaries;
- direct-message packet fragmentation/reassembly state transitions;
- lower-level session send/receive/refresh/close state transitions.

The seed corpus includes frozen persistence vectors, parser-stress vectors, magic prefixes, empty/minimal inputs, and deterministic mutations of every seed. Increase the bounded mutation count with:

```bash
HYDRA_FUZZ_CASES=64 ./qa/ci/fuzz/check-fuzz.sh
```

## Coverage-guided fuzzing

The `cargo-fuzz/` directory contains the release-candidate libFuzzer harness. Because it intentionally lives outside cargo-fuzz's conventional root `fuzz/` directory, the QA runners pass `--fuzz-dir qa/fuzz/cargo-fuzz` explicitly. Cargo-fuzz's sanitizer coverage requires nightly Rust, so the runners select `nightly` for the complete cargo-fuzz subprocess tree. Override that only with another installed nightly toolchain through `HYDRA_FUZZ_TOOLCHAIN`. Run release fuzz evidence through the full gate:

```bash
./qa/ci/check-all.sh
```

`check-all` sets `HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1` and defaults to `HYDRA_COVERAGE_FUZZ_RUNS=100000`. Run `qa/ci/fuzz/check-fuzz.*` directly only when debugging fuzz in isolation.

Install the required toolchain and cargo-fuzz with `scripts/setup-dev-env.*`, or manually:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

The harness covers envelope headers, protected records, message codec paths, storage/backup chunks, contact cards, handshakes, lobby invites, anonymous-auth tokens, fragment reassembly, session receive state machines, and group commit/message paths. Evidence is written to `target/hydra-fuzz-evidence/`. See [`docs/validation/gates/coverage-guided-fuzzing.md`](../../docs/validation/gates/coverage-guided-fuzzing.md).

## Not a replacement for release campaigns

The bounded direct gate proves that a fixed corpus and deterministic mutations do not panic the parser/codec/state-transition surface. Release assurance also requires the long coverage-guided campaign, sanitizer runs, and crash minimization evidence produced by the full `check-all` gate.
