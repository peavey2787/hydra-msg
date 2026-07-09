# HYDRA-MSG manual validation gate

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)

Status: P13 manual validation gate.

P13 is intentionally manual. It does not add product features or change the public API. It verifies that the maintainer-selected release-candidate worktree is clean on a real developer machine with Rust/Cargo/WASM tools installed.

## Required local checks

Run the full workspace validation from the repository root. `check-all` is the top-level gate; it calls `check-tests` first, then `check-examples`.

Windows PowerShell:

```powershell
.\qa\ci\check-all.ps1
```

Unix shell:

```bash
./qa/ci/check-all.sh
```

Run the tests/static gate without examples when isolating test failures.

Windows PowerShell:

```powershell
.\qa\ci\check-tests.ps1
```

Unix shell:

```bash
./qa/ci/check-tests.sh
```

Run runnable examples and browser package checks directly when isolating example failures.

Windows PowerShell:

```powershell
.\qa\ci\check-examples.ps1
```

Unix shell:

```bash
./qa/ci/check-examples.sh
```

The example script runs every package under `examples/`: native facade examples, all `hydra-app-core` examples, the `hydra-app` help path, browser host compile checks, loopback smoke runs for long-running browser hosts, and example-local WASM package builds. If you are isolating native examples only, pass `-SkipWasm` on PowerShell or `--skip-wasm` on Unix.

Build the reusable web package separately when validating app-facing WASM output:

```powershell
.\qa\ci\build-wasm-web.ps1
```

Unix shell:

```bash
./qa/ci/build-wasm-web.sh
```

That package is written to `target/hydra-msg-wasm/web/`.

The WebRTC carrier example still requires a manual browser run to confirm manual contact-card exchange and DataChannel message flow:

```bash
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

The mobile benchmark host can be run manually after the example package build:

```bash
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

## Pass condition

P13 passes only when:

- formatting is clean;
- workspace tests pass;
- clippy passes with `-D warnings`;
- active examples run;
- reusable WASM web package builds;
- example-local WASM packages build during example validation;
- WebRTC carrier host serves and manual contact-card exchange works;
- no runtime `hydra-msg-data/` or local identity material is staged;
- benchmark numbers are recorded or updated in `docs/validation/benchmark-results.md` if they materially differ.

Passing P13 means the repository is ready to consider a release tag. It does not imply independent cryptographic audit or external interoperability certification.
