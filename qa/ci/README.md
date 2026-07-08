# HYDRA-MSG CI helpers

Reusable local/CI scripts for validation, examples, vector checks, and WASM builds.

## Navigation

- [Main README](../../README.md)
- [QA workspace](../README.md)
- [Examples](../../examples/README.md)
- [WASM/JavaScript bindings](../../crates/hydra-msg-wasm/README.md)
- [Validation docs](../../docs/validation/release-criteria.md)

## Scripts

| Script | Purpose |
|---|---|
| `check-all.ps1` / `check-all.sh` | Full validation gate. |
| `check-examples.ps1` / `check-examples.sh` | Runnable examples and browser package checks. |
| `build-wasm-web.ps1` / `build-wasm-web.sh` | Reusable WASM web package builder. |
| `linux-permissions.sh` | Restores Unix execute bits and repairs stale Git worktree metadata after ZIP extraction. |
| `check-rust.sh` | Workspace format, test, and clippy gate. |
| `check-docs.sh` | Docs/static checks. |
| `check-locks.sh` | Lock-file alignment checks for offline validation. |
| `check-vectors.sh` | Vector generator and candidate manifest verification. |

## Full validation

Unix:

```bash
sh qa/ci/linux-permissions.sh
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

## Example validation

Unix:

```bash
./qa/ci/check-examples.sh
```

PowerShell:

```powershell
.\qa\ci\check-examples.ps1
```

Skip WASM package checks while debugging native examples:

```bash
./qa/ci/check-examples.sh --skip-wasm
```

```powershell
.\qa\ci\check-examples.ps1 -SkipWasm
```

## Reusable WASM web package

Unix:

```bash
./qa/ci/build-wasm-web.sh
```

PowerShell:

```powershell
.\qa\ci\build-wasm-web.ps1
```

Output:

```text
target/hydra-msg-wasm/web/
```

Example validation builds example-local `web/pkg/` directories only when running `check-examples`.

## Offline note

Vector checks use the isolated vector-tool lock file with `--offline`. `check-locks.sh` verifies vector-tool package versions are present in the main workspace lock so a normal workspace build primes the local Cargo cache for vector validation.
