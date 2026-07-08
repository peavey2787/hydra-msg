# HYDRA-MSG scripts

Reusable local scripts for checks, examples, vector checks, and browser package builds.

## Navigation

- [Main README](../../README.md)
- [Parent workspace](../README.md)

## Scripts

| Script | Purpose |
|---|---|
| `check-all.ps1` / `check-all.sh` | Full local check gate. |
| `check-examples.ps1` / `check-examples.sh` | Runnable examples and browser package checks. |
| `build-wasm-web.ps1` / `build-wasm-web.sh` | Reusable web package builder. |
| `linux-permissions.sh` | Restores Unix execute bits and repairs stale Git worktree metadata after ZIP extraction. |
| `check-rust.sh` | Workspace format, test, and clippy gate. |
| `check-docs.sh` | Docs/static checks, README navigation, and local Markdown link resolution. |
| `check-rust-file-sizes.ps1` / `check-rust-file-sizes.sh` | `hydra-group` Rust source-size ownership checks with documented exceptions. |
| `check-markdown-links.ps1` / `check-markdown-links.sh` | Local Markdown link resolver used by docs checks. |
| `check-locks.sh` | Lock-file alignment checks for offline validation. |
| `check-vectors.sh` | Vector generator and candidate manifest verification. |

## Full local check

Unix:

```bash
sh qa/ci/linux-permissions.sh
./qa/ci/check-all.sh
```

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

## Example checks

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

## Reusable web package

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
