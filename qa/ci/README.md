# HYDRA-MSG CI helpers

Status: active CI support directory.

This directory contains reusable CI/local-check scripts for HYDRA-MSG. The
GitHub Actions workflow under `.github/workflows/`, if added, should remain a
thin entrypoint that calls scripts from this directory. The real check logic
belongs here so it can be run locally and in CI the same way.

## Available checks

```text
check-all.ps1      # Windows PowerShell full validation gate
check-all.sh       # Unix shell full validation gate
check-examples.ps1 # Windows PowerShell runnable example/browser package gate
check-examples.sh  # Unix shell runnable example/browser package gate
check-rust.sh      # workspace fmt/test/clippy gate
check-docs.sh      # docs/path/stale-term/source-marker gate
check-vectors.sh   # vector generator + candidate manifest verification
```

## Windows validation gates

Run the full non-interactive workspace validation from PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

Run runnable examples and browser package checks separately:

```powershell
.\qa\ci\check-examples.ps1
```

By default, the PowerShell full gate runs `cargo fmt` before tests so local check runs also clean up formatting. To enforce formatting without modifying files, use:

```powershell
.\qa\ci\check-all.ps1 -CheckFormatOnly
```

Skip isolated vector checks only when debugging app-only failures:

```powershell
.\qa\ci\check-all.ps1 -SkipVectors
```

`-SkipVectors` is not sufficient for P13 completion. The full P13 gate includes vector checks.

## Unix validation gates

```sh
qa/ci/check-all.sh
qa/ci/check-examples.sh
```

## Evidence rule

Script existence is not evidence that validation passed. Passing evidence is the
successful output from running the relevant script on the active repo state.


Vector formatting: `check-vectors.sh` formats by default. Use `check-vectors.sh --check-format` for strict format-check mode. PowerShell strict format mode is `check-all.ps1 -CheckFormatOnly`. Example scripts require `wasm-pack` for browser package checks unless you pass `-SkipWasm` or `--skip-wasm`.
