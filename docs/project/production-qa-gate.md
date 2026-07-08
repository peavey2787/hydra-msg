# HYDRA-MSG manual validation gate

Status: P13 manual validation gate.

P13 is intentionally manual. It does not add product features or change the public API. It verifies that the release-candidate worktree produced by the roadmap is clean on a real developer machine with Rust/Cargo/WASM tools installed.

## Required local checks

Run from the repository root:

```bash
cargo fmt
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Run the active native examples:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
cargo run --manifest-path examples/contact_card/Cargo.toml
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
```

Build and run the WASM benchmark host:

```bash
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Build and run the WebRTC carrier host:

```bash
examples/webrtc_manual_carrier/scripts/build-wasm.sh
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

On Windows PowerShell, use the `.ps1` script in the same carrier example directory.

## Required documentation checks

Run the repository QA scripts if your platform supports them:

```bash
qa/ci/check-all.sh
```

or on PowerShell:

```powershell
qa\ci\check-all.ps1
```

## Pass condition

P13 passes only when:

- formatting is clean;
- workspace tests pass;
- clippy passes with `-D warnings`;
- active examples run;
- WASM package builds;
- WebRTC carrier host serves and manual contact-card exchange works;
- no runtime `hydra-msg-data/` or local identity material is staged;
- benchmark numbers are recorded or updated in `docs/project/benchmark-results.md` if they materially differ.

Passing P13 means the repository is ready to consider a release tag. It does not imply independent cryptographic audit or external interoperability certification.
