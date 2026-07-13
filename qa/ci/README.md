# HYDRA-MSG CI scripts

Reusable local scripts for checks, examples, vector checks, supply-chain policy, fuzzing, and browser package builds.

## Navigation

- [Main README](../../README.md)
- [Parent QA README](../README.md)

## Layout

Only the main orchestrators live at the `qa/ci/` top level:

```text
qa/ci/
├── check-all.sh
├── check-all.ps1
├── README.md
├── core/         Rust workspace, examples, WASM package build, and Linux setup helpers
├── policy/       docs, links, lock files, vectors, and source-size ownership gates
├── security/     privacy, metadata, resource-limit, and persistence invariant gates
├── reliability/  crash consistency, memory-safety, browser lifecycle, interop, compatibility, and mobile-web gates
├── quality/      coverage and mutation target gates
├── fuzz/         deterministic plus coverage-guided fuzzing; called last by check-all
├── release/      release-governance and package/signing policy checks
└── lib/          shared CI helpers
```


## First-time developer setup

Install HYDRA's required Rust QA tools, WASM tooling, and optional nightly Miri/sanitizer components with:

```bash
./scripts/setup-dev-env.sh
```

PowerShell:

```powershell
.\scripts\setup-dev-env.ps1
```

## Top-level gate

`check-all` is the full release validation runner. With no flags, it runs every validation section in order and stops on the first failure. It calls tests/static validation first, then example/browser package validation, then the expensive release-evidence gates near the bottom: Miri, sanitizers, real-browser Playwright, coverage, mutation testing, and finally the bounded coverage-guided fuzz campaign. Supply-chain evidence is included inside `core/check-tests.*` through `security/check-supply-chain.*`.

Unix:

```bash
sh qa/ci/core/linux-permissions.sh
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

The Unix runner supports section-aware resume and granular skips:

```bash
./qa/ci/check-all.sh --list-sections
./qa/ci/check-all.sh --from browser --skip-browser-install
./qa/ci/check-all.sh --resume-from browser --skip-browser-install
./qa/ci/check-all.sh --from coverage --through mutation
./qa/ci/check-all.sh --from mutation --skip-mutation-baseline
./qa/ci/check-all.sh --only fuzz
./qa/ci/check-all.sh --only fuzz --overnight
./qa/ci/check-all.sh --only fuzz --deep-fuzz
./qa/ci/check-all.sh --section fuzz --fuzz-runs 1000
```

Sections run in this order: `permissions`, `tests`, `examples`, `miri`, `sanitizers`, `browser`, `coverage`, `mutation`, `fuzz`. Run `./qa/ci/check-all.sh --help` for all `--skip-*` flags.
Use `--skip-mutation-baseline` only after the same tree has already passed its Rust tests; cargo-mutants then uses the explicit per-mutant timeout from `--mutation-timeout` (default 1200 seconds). Normal mutation runs measure the clean baseline and derive the timeout automatically.

## What `check-all` includes

`check-all` is intentionally long-running because it is the release-complete gate. It includes:

```text
workspace fmt/test/clippy
supply-chain cargo-audit/cargo-deny
source-size, docs, locks, vectors, resource limits, metadata, persistence, privacy, interop, compatibility
examples and WASM package checks
Miri release evidence
sanitizer release evidence
real-browser Playwright lifecycle evidence
coverage report evidence
mutation testing evidence
bounded coverage-guided fuzz evidence, last
```

The default fuzz mode runs 256 iterations per target. Longer modes are explicit:

```bash
./qa/ci/check-all.sh --only fuzz --overnight
./qa/ci/check-all.sh --only fuzz --deep-fuzz
```

```powershell
.\qa\ci\check-all.ps1 -Only fuzz -Overnight
.\qa\ci\check-all.ps1 -Only fuzz -DeepFuzz
```

## Core scripts

| Script | Purpose |
|---|---|
| `core/check-tests.ps1` / `core/check-tests.sh` | Tests/static checks only. `check-all` calls this with release-heavy static probes deferred so the real Miri, sanitizer, browser, coverage, mutation, and fuzz sections run later. |
| `core/check-rust.sh` | Committed-lock metadata validation, workspace `cargo fmt --check`, `cargo test --workspace --all-targets`, and `cargo clippy --workspace --all-targets -- -D warnings`. |
| `core/check-examples.ps1` / `core/check-examples.sh` | Runs every package under `examples/`, including app-core examples, app help, browser host smoke runs, and browser package checks. |
| `core/build-wasm-web.ps1` / `core/build-wasm-web.sh` | Reusable web package builder. |
| `core/linux-permissions.sh` | Restores Unix execute bits and repairs stale Git worktree metadata after ZIP extraction. |

## Policy scripts

| Script | Purpose |
|---|---|
| `policy/check-docs.sh` | Docs/static checks, README/product-doc navigation, stale terminology checks, and local Markdown link resolution. |
| `policy/check-markdown-links.ps1` / `policy/check-markdown-links.sh` | Local Markdown link resolver used by docs checks. |
| `policy/check-rust-file-sizes.ps1` / `policy/check-rust-file-sizes.sh` | Rust source-size ownership checks across `crates/` with documented exceptions in `policy/rust-size-allowlist.txt`. |
| `policy/check-locks.sh` | Lock-file coverage checks plus shared-version conflict checks between the root lock and the independent vector-tool lock. Vector-tool-only transitives are allowed. |
| `policy/check-vectors.sh` | Vector generator and candidate manifest verification. |

## Security scripts

| Script | Purpose |
|---|---|
| `security/check-supply-chain.ps1` / `security/check-supply-chain.sh` | Verifies the committed root lock with `cargo fetch --locked` for local/release validation, with an explicit `HYDRA_CI_EPHEMERAL_LOCK_REFRESH=1` escape hatch for normal bounded GitHub CI. Then runs cargo-audit, cargo-deny, license allowlist, advisory, yanked-crate, ban, and source provenance gates. |
| `security/check-privacy-invariants.ps1` / `security/check-privacy-invariants.sh` | Static implementation privacy guardrails for facade handshake and hardened boundaries. |
| `security/check-resource-limits.ps1` / `security/check-resource-limits.sh` | Hostile-input sizes, bounded retained state/work, sparse fragment reassembly, and adversarial resource-limit tests. |
| `security/check-metadata-leakage.ps1` / `security/check-metadata-leakage.sh` | Formal metadata-leakage audit gate. |
| `security/check-persistence-api-shape.ps1` / `security/check-persistence-api-shape.sh` | Passworded backup verification API and explicit WASM persistent/ephemeral/flush boundary. |
| `security/check-persistence-invariants.ps1` / `security/check-persistence-invariants.sh` | Encrypted snapshot parser ownership, parser-stress vectors, no legacy plaintext state, no `localStorage` HYDRA state, and no stale passwordless backup verification. |

## Reliability scripts

| Script | Purpose |
|---|---|
| `reliability/check-crash-consistency.ps1` / `reliability/check-crash-consistency.sh` | Crash-consistency matrix gate. |
| `reliability/check-memory-safety.ps1` / `reliability/check-memory-safety.sh` | Mandatory fault-injection tests plus optional `HYDRA_RUN_MIRI=1` Miri and `HYDRA_RUN_SANITIZERS=1` sanitizer gates. |
| `reliability/check-browser-lifecycle.ps1` / `reliability/check-browser-lifecycle.sh` | WASM/browser lifecycle and IndexedDB persistence gate; also invokes the browser E2E static gate. |
| `reliability/check-browser-e2e.ps1` / `reliability/check-browser-e2e.sh` | Playwright real-browser lifecycle evidence, optional via `HYDRA_RUN_BROWSER_E2E=1`. |
| `reliability/check-interop.ps1` / `reliability/check-interop.sh` | Cross-runtime interop harness for frozen packet/state/backup fixtures, native/WASM compatibility, CLI fixture opening, and old-fixture contracts. |
| `reliability/check-cross-version-compat.ps1` / `reliability/check-cross-version-compat.sh` | Cross-version compatibility gate for frozen state/backup fixtures, rollback evidence, unknown future records, and packet-fragment receive semantics. |
| `reliability/check-mobile-perf-web.ps1` / `reliability/check-mobile-perf-web.sh` | Static guardrails for the mobile browser benchmark and IndexedDB persistence validation harness. |

## Quality and fuzz scripts

| Script | Purpose |
|---|---|
| `quality/check-coverage.ps1` / `quality/check-coverage.sh` | Critical-path coverage manifest gate, plus optional `HYDRA_RUN_COVERAGE=1` LCOV/HTML coverage generation and threshold enforcement. |
| `quality/check-mutation.ps1` / `quality/check-mutation.sh` | Mutation-target manifest gate, plus optional `HYDRA_RUN_MUTATION=1` cargo-mutants run over the manifest-listed critical files. The measured run uses a baseline-derived timeout rather than a fixed baseline cutoff. |
| `fuzz/check-fuzz.ps1` / `fuzz/check-fuzz.sh` | Bounded deterministic fuzz-smoke gate plus nightly cargo-fuzz/libFuzzer release campaigns. Local/release runs use `cargo run --locked`; normal bounded GitHub CI may set `HYDRA_CI_EPHEMERAL_LOCK_REFRESH=1` to use the freshly resolved CI lock graph. The scripts propagate `HYDRA_FUZZ_TOOLCHAIN` (default `nightly`) into cargo-fuzz's nested Cargo build. `check-all` calls this last with `HYDRA_RUN_COVERAGE_GUIDED_FUZZ=1`. Smoke mode defaults to 256 runs per target; overnight mode is time-bounded; deep mode uses 100,000 runs for fast targets and 1,000 for the slow stateful target. |
| `release/check-release-governance.ps1` / `release/check-release-governance.sh` | Static release-governance gate for changelog, security policy, MSRV, SBOM/signing/reproducible-build docs, and release helper scripts. |

## Common commands

Tests/static only:

```bash
./qa/ci/core/check-tests.sh
```

```powershell
.\qa\ci\core\check-tests.ps1
```

Examples only:

```bash
./qa/ci/core/check-examples.sh
```

```powershell
.\qa\ci\core\check-examples.ps1
```

Skip WASM package checks while debugging native examples:

```bash
./qa/ci/core/check-examples.sh --skip-wasm
```

```powershell
.\qa\ci\core\check-examples.ps1 -SkipWasm
```

Reusable web package:

```bash
./qa/ci/core/build-wasm-web.sh
```

```powershell
.\qa\ci\core\build-wasm-web.ps1
```

Output:

```text
target/hydra-msg-wasm/web/
```


## Release packaging/signing helpers

Create, sign, and verify release artifacts from a signed tag:

```bash
scripts/release/create-signed-tag.sh vX.Y.Z [gpg-key-id]
scripts/release/create-release-package.sh vX.Y.Z
scripts/release/sign-release-artifacts.sh vX.Y.Z [gpg-key-id]
scripts/release/verify-release-artifacts.sh vX.Y.Z
```

PowerShell:

```powershell
.\scripts\release\create-signed-tag.ps1 vX.Y.Z [gpg-key-id]
.\scripts\release\create-release-package.ps1 vX.Y.Z
.\scripts\release\sign-release-artifacts.ps1 vX.Y.Z [gpg-key-id]
.\scripts\release\verify-release-artifacts.ps1 vX.Y.Z
```
