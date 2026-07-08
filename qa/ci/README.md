# HYDRA-MSG CI helpers

Status: active CI support directory.

This directory contains reusable CI/local-check scripts for HYDRA-MSG. The
GitHub Actions workflow under `.github/workflows/`, if added, should remain a
thin entrypoint that calls scripts from this directory. The real check logic
belongs here so it can be run locally and in CI the same way.

## Available checks

```text
check-all.ps1       # Windows PowerShell full validation gate
check-all.sh        # Unix shell full validation gate
build-wasm-web.ps1  # Windows reusable WASM web package builder
build-wasm-web.sh   # Unix reusable WASM web package builder
linux-permissions.sh # Unix helper that restores execute bits and stale worktree metadata after ZIP extraction
check-examples.ps1  # Windows PowerShell runnable example/browser package gate
check-examples.sh   # Unix shell runnable example/browser package gate
check-rust.sh       # workspace fmt/test/clippy gate
check-docs.sh      # docs/path/stale-term/source-marker gate
check-locks.sh     # lock-file alignment checks for offline validation
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

After extracting a ZIP on Linux/macOS, restore script permissions and repair stale Git worktree metadata once:

```sh
sh qa/ci/linux-permissions.sh
```

Then run the full gate from the repo root:

```sh
./qa/ci/check-all.sh
```

Run examples separately:

```sh
./qa/ci/check-examples.sh
```

Skip WASM package checks while debugging native examples:

```sh
./qa/ci/check-examples.sh --skip-wasm
```

Do not run these scripts with `sudo` unless your Rust toolchain is installed for root.

If Git ever resolves the repo to a trashed or old path, rerun:

```sh
sh qa/ci/linux-permissions.sh
git rev-parse --show-toplevel
```

The printed root should match the directory where the ZIP was extracted.


## Reusable WASM web package

Build the reusable browser/mobile package from the repo root:

```powershell
.\qa\ci\build-wasm-web.ps1
```

Unix:

```sh
./qa/ci/build-wasm-web.sh
```

Output:

```text
target/hydra-msg-wasm/web/
```

Example validation still builds example-local `web/pkg/` directories only when running `check-examples`.

## Evidence rule

Script existence is not evidence that validation passed. Passing evidence is the
successful output from running the relevant script on the active repo state.


Offline note: vector checks use the isolated vector-tool lock file with `--offline`. `check-locks.sh` verifies every vector-tool package version is already present in the main workspace lock, so a normal workspace build primes the local Cargo cache for vector validation.

Vector formatting: `check-vectors.sh` formats by default. Use `check-vectors.sh --check-format` for strict format-check mode. PowerShell strict format mode is `check-all.ps1 -CheckFormatOnly`. Example scripts require `wasm-pack` for browser package checks unless you pass `-SkipWasm` or `--skip-wasm`.
