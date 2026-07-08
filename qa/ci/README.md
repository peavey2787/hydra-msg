# HYDRA-MSG CI helpers

Status: active CI support directory.

This directory contains reusable CI/local-check scripts for HYDRA-MSG. The
GitHub Actions workflow under `.github/workflows/`, if added, should remain a
thin entrypoint that calls scripts from this directory. The real check logic
belongs here so it can be run locally and in CI the same way.

## Available checks

```text
check-all.ps1   # Windows PowerShell production QA gate
check-all.sh    # Unix shell production QA gate
check-rust.sh   # workspace fmt/test/clippy gate
check-docs.sh   # docs/path/stale-term/source-marker gate
check-vectors.sh# vector generator + candidate manifest verification
```

## Windows production QA gate

Run all non-interactive production checks from PowerShell:

```powershell
.\qa\ci\check-all.ps1 -SkipGui
```

Run all checks and then launch the GUI:

```powershell
.\qa\ci\check-all.ps1
```

By default, the PowerShell gate runs `cargo fmt` before tests so local check runs also clean up formatting. To enforce formatting without modifying files, use:

```powershell
.\qa\ci\check-all.ps1 -CheckFormatOnly -SkipGui
```

Skip isolated vector checks only when debugging app-only failures:

```powershell
.\qa\ci\check-all.ps1 -SkipGui -SkipVectors
```

`-SkipVectors` is not sufficient for P13 completion. The full P13 gate includes
vector checks.

## Unix production QA gate

```sh
qa/ci/check-all.sh
```

## Evidence rule

Script existence is not evidence that validation passed. Passing evidence is the
successful output from running the relevant script on the active repo state.


Vector formatting: `check-vectors.sh` formats by default. Use `check-vectors.sh --check-format` for strict format-check mode. PowerShell strict format mode is `check-all.ps1 -CheckFormatOnly`.
