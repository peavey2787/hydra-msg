# HYDRA-MSG scripts

Reusable local scripts for checks, examples, vector checks, and browser package builds.

## Navigation

- [Main README](../../README.md)
- [Parent workspace](../README.md)

## Scripts

| Script | Purpose |
|---|---|
| `check-all.ps1` / `check-all.sh` | Full local gate: tests/static checks plus runnable examples/browser package checks. |
| `check-tests.ps1` / `check-tests.sh` | Tests/static checks only: workspace Rust checks, docs, source-size ownership, locks, and vectors. |
| `check-examples.ps1` / `check-examples.sh` | Runs every package under `examples/`, including app-core examples, app help, browser host smoke runs, and browser package checks. |
| `build-wasm-web.ps1` / `build-wasm-web.sh` | Reusable web package builder. |
| `linux-permissions.sh` | Restores Unix execute bits and repairs stale Git worktree metadata after ZIP extraction. |
| `check-rust.sh` | Workspace format, test, and clippy gate. |
| `check-docs.sh` | Docs/static checks, README/product-doc navigation, and local Markdown link resolution. |
| `check-rust-file-sizes.ps1` / `check-rust-file-sizes.sh` | `hydra-group` and `hydra-msg` Rust source-size ownership checks with documented exceptions. |
| `check-privacy-invariants.ps1` / `check-privacy-invariants.sh` | Static implementation privacy guardrails for the facade handshake and other hardened boundaries. |
| `check-markdown-links.ps1` / `check-markdown-links.sh` | Local Markdown link resolver used by docs checks. |
| `check-locks.sh` | Lock-file alignment checks for offline validation. |
| `check-vectors.sh` | Vector generator and candidate manifest verification. |

## Full local check

`check-all` is the thin top-level runner. It calls `check-tests` first, then `check-examples`.

Unix:

```bash
sh qa/ci/linux-permissions.sh
./qa/ci/check-all.sh
```

Linux desktop launcher:

```bash
./run-check-all-linux.sh
```

You can also double-click `run-check-all-linux.desktop` on desktops that trust executable `.desktop` launchers. It opens a terminal, finds the first `~/Downloads/hydra*` folder containing `qa/ci/check-all.sh`, and runs the full gate there.

PowerShell:

```powershell
.\qa\ci\check-all.ps1
```


## Tests-only check

Use this when you want the full non-example gate without running examples or browser package builds.

Unix:

```bash
./qa/ci/check-tests.sh
```

PowerShell:

```powershell
.\qa\ci\check-tests.ps1
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


`check-examples` is the official examples gate. Every `examples/*/Cargo.toml` package must appear in this script. Long-running browser host examples are smoke-run on loopback and then stopped; browser WASM packages are built unless skipped.

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
