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
```

Run them from the repo root:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
cargo run --manifest-path examples/contact_card/Cargo.toml
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

## Browser/mobile WASM facade benchmark

Build the WASM binding package and run the LAN benchmark host:

```bash
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Then open the LAN URL from a phone/tablet/browser and click **Run browser/device HYDRA WASM benchmark**.

## Demo reference material

The retired old `hydra-app-core` and `hydra-app` demo crates are kept under:

```text
examples/hydra-app-core
examples/hydra-app
```

They are not active workspace members, not release targets, and not public API authority. Do not add new flows there; write new examples against `crates/hydra-msg` instead.
