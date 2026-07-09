# HYDRA-MSG examples

`examples/` contains runnable examples over the public `hydra-msg` SDK.

Examples show how app code moves opaque HYDRA bytes over different carriers. Protocol authority stays in `crates/` and `docs/spec/`.

## Navigation

- [Main README](../README.md)
- [How HYDRA messaging works](../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../docs/spec/README.md)
- [Crates](../crates/README.md)
- [Examples](README.md)
- [Public developer API](../docs/spec/public-developer-api.md)
- [Benchmark notes](../docs/validation/benchmark-results.md)

## Example list

| Example | Purpose |
|---|---|
| [handshake_roundtrip](handshake_roundtrip/README.md) | Two identities, contact cards, handshake, send/receive. |
| [contact_card](contact_card/README.md) | Contact-card create/add/verify/export/import flow. |
| [attachment_roundtrip](attachment_roundtrip/README.md) | Text plus file and byte attachments. |
| [lobby_roundtrip](lobby_roundtrip/README.md) | Lobby invite and recipient-tagged lobby send/receive. |
| [manual_file_carrier](manual_file_carrier/README.md) | Files on disk as a manual opaque-byte carrier. |
| hydra-app-core | Lower-level app architecture examples used by the local example gate. |
| hydra-app | CLI/local GUI reference app used by the local example gate. |
| [mobile_perf_web](mobile_perf_web/README.md) | LAN browser/device WASM benchmark host. |
| [webrtc_manual_carrier](webrtc_manual_carrier/README.md) | WebRTC DataChannel carrier after manual contact-card exchange. |

## Run native examples

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
cargo run --manifest-path examples/contact_card/Cargo.toml
cargo run --manifest-path examples/attachment_roundtrip/Cargo.toml
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
cargo run --manifest-path examples/manual_file_carrier/Cargo.toml
cargo run --manifest-path examples/hydra-app/Cargo.toml -- help
```

`check-examples` is the source of truth for full example coverage. It also runs all `hydra-app-core` examples, smoke-runs the browser host packages, and builds the example WASM packages unless WASM is explicitly skipped.

## Run all example checks

Unix:

```bash
./qa/ci/check-examples.sh
```

PowerShell:

```powershell
.\qa\ci\check-examples.ps1
```

Use `--skip-wasm` on Unix or `-SkipWasm` on PowerShell for native-only example checks.

## Reusable browser package

The real browser/mobile component lives in `crates/hydra-msg-wasm`.

Build reusable web output for your own app:

```bash
./qa/ci/build-wasm-web.sh
```

Output:

```text
target/hydra-msg-wasm/web/
```

Example browser hosts build their own `web/pkg/` folders only when testing those examples.
