# HYDRA-MSG examples

This directory contains runnable examples over the public `hydra-msg` facade.

Examples are **not protocol authority**. They demonstrate how app developers move opaque HYDRA bytes over any carrier.

## Active stupid-simple examples

```text
examples/handshake_roundtrip     two identities, contact cards, handshake, send/receive
examples/contact_card            contact-card create/add/verify/export/import flow
examples/attachment_roundtrip    text + file attachment + in-memory byte attachment
examples/lobby_roundtrip         lobby invite + recipient-tagged lobby send/receive
examples/mobile_perf_web         LAN browser/device WASM benchmark host
examples/manual_file_carrier     files on disk as a manual opaque-byte carrier
examples/webrtc_manual_carrier   WebRTC DataChannel carrier after manual contact-card exchange
```

Run the native examples from the repo root:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
cargo run --manifest-path examples/contact_card/Cargo.toml
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
```


## Run all example checks

From the repo root, run:

```powershell
.\qa\ci\check-examples.ps1
```

Unix:

```bash
qa/ci/check-examples.sh
```

The script runs the native examples, checks the browser host examples, and builds WASM packages with `wasm-pack`. For native-only example checks, use `-SkipWasm` on PowerShell or `--skip-wasm` on Unix.

## Browser/mobile WASM facade benchmark

Build the WASM binding package and run the LAN benchmark host:

```bash
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Then open the LAN URL from a phone/tablet/browser and click **Run browser/device HYDRA WASM benchmark**.

## WebRTC manual carrier

Build the WASM binding package and run the WebRTC carrier host:

```bash
examples/webrtc_manual_carrier/scripts/build-wasm.sh
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

Or on Windows PowerShell:

```powershell
examples\webrtc_manual_carrier\scripts\build-wasm.ps1
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

Contact cards are exchanged manually and out-of-band. WebRTC only carries HYDRA handshake bytes and encrypted envelopes after both users import/verify each other's contact cards.

## Demo reference material

The `hydra-app-core` and `hydra-app` demo crates are kept under:

```text
examples/hydra-app-core
examples/hydra-app
```

They are not active workspace members, not release targets, and not public API authority. Do not add new flows there; write new examples against `crates/hydra-msg` instead.

Carrier ownership and carrier example rules are documented in `../docs/project/carrier-examples.md`.
