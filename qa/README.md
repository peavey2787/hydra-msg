# HYDRA-MSG checks

`qa/` contains local scripts, system tests, gate-owned evidence notes, vector tooling, and fuzzing workspace folders.

## Navigation

- [Main README](../README.md)

## Contents

```text
qa/
├── browser/   Playwright browser lifecycle evidence harness
├── ci/        grouped local-check scripts; check-all stays at top level
├── coverage/  critical-path coverage thresholds and LCOV enforcement helper
├── evidence/  gate-owned evidence notes used by validation scripts
├── fixtures/  fixed validation fixtures, including cross-runtime interop fixtures
├── fuzz/      fuzzing workspace
├── mutation/  mutation-testing targets for release CI
├── tests/     global/system test crates
├── vectors/   generated vector artifacts
└── tools/     validation and vector-generation tooling
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

## Main commands

`check-all` is the release-complete gate. The individual scripts are useful for debugging one failing area, but the release path is `check-all`.

Unix:

```bash
sh qa/ci/core/linux-permissions.sh
./qa/ci/check-all.sh
./qa/ci/core/check-tests.sh
./qa/ci/core/check-examples.sh
./qa/ci/fuzz/check-fuzz.sh
./qa/ci/security/check-supply-chain.sh
./qa/ci/security/check-resource-limits.sh
./qa/ci/reliability/check-memory-safety.sh
./qa/ci/reliability/check-interop.sh
./qa/ci/quality/check-coverage.sh
./qa/ci/quality/check-mutation.sh
./qa/ci/reliability/check-cross-version-compat.sh
./qa/ci/reliability/check-browser-e2e.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
.\qa\ci\core\check-tests.ps1
.\qa\ci\core\check-examples.ps1
.\qa\ci\fuzz\check-fuzz.ps1
.\qa\ci\security\check-supply-chain.ps1
.\qa\ci\security\check-resource-limits.ps1
.\qa\ci\reliability\check-memory-safety.ps1
.\qa\ci\reliability\check-interop.ps1
.\qa\ci\quality\check-coverage.ps1
.\qa\ci\quality\check-mutation.ps1
.\qa\ci\reliability\check-cross-version-compat.ps1
```


## Release evidence

`qa/ci/check-all.*` includes the long-running release-evidence gates. It runs Miri, sanitizers, real-browser Playwright E2E, coverage, mutation testing, and the overnight coverage-guided fuzz campaign. The fuzz campaign is intentionally last and defaults to 100,000 libFuzzer runs per target.

Use the individual scripts only when debugging one failing gate or intentionally collecting isolated evidence. The Unix runner can resume at a release section and can skip already-collected evidence:

```bash
./qa/ci/check-all.sh --from browser --skip-browser-install
./qa/ci/check-all.sh --from coverage
./qa/ci/check-all.sh --only mutation
./qa/ci/check-all.sh --help
```

```bash
HYDRA_COVERAGE_FUZZ_RUNS=10000 ./qa/ci/check-all.sh
```

PowerShell:

```powershell
$env:HYDRA_COVERAGE_FUZZ_RUNS = "10000"
.\qa\ci\check-all.ps1
```

To include the full WASM app probe in browser E2E, set `HYDRA_BROWSER_TEST_URL` to a running `examples/mobile_perf_web` host before running `check-all`.

## Release artifact process

After all normal and heavy gates are green, create the signed release package with:

```bash
scripts/release/create-signed-tag.sh vX.Y.Z [gpg-key-id]
scripts/release/create-release-package.sh vX.Y.Z
scripts/release/sign-release-artifacts.sh vX.Y.Z [gpg-key-id]
scripts/release/verify-release-artifacts.sh vX.Y.Z
```
