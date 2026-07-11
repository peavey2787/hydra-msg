# HYDRA-MSG examples

`examples/` contains runnable applications and carrier demonstrations built on the public `hydra-msg` SDK.

Protocol authority remains in `crates/` and `docs/spec/`. Example applications must treat handshake, direct-message, and lobby packet bytes as opaque carrier payloads.

## Navigation

- [Main README](../README.md)
- [How HYDRA messaging works](../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../docs/spec/README.md)
- [Crates](../crates/README.md)
- [Examples](README.md)
- [Public developer API](../docs/spec/public-developer-api.md)
- [Benchmark notes](../docs/validation/benchmarks/benchmark-results.md)

## Example list

| Example | Purpose |
|---|---|
| [handshake_roundtrip](handshake_roundtrip/README.md) | Two identities, contact cards, handshake, send/receive. |
| [contact_card](contact_card/README.md) | Contact-card create/add/verify/export/import flow. |
| [attachment_roundtrip](attachment_roundtrip/README.md) | Text plus file and byte attachments. |
| [lobby_roundtrip](lobby_roundtrip/README.md) | Lobby invite and recipient-tagged lobby send/receive. |
| [manual_file_carrier](manual_file_carrier/README.md) | Files on disk as a manual opaque-byte carrier. |
| [hydra-gui](hydra-gui/README.md) | Current production reference app over the public SDK. |
| [mobile_perf_web](mobile_perf_web/README.md) | LAN browser/device WASM benchmark host. |
| [webrtc_manual_carrier](webrtc_manual_carrier/README.md) | WebRTC DataChannel carrier after manual contact-card exchange. |

## Run the reference app

```bash
cargo run --manifest-path examples/hydra-gui/hydra-app/Cargo.toml -- help
```

The full example gate runs the reference-app integration tests, three public-SDK app examples, all other native examples, browser-host smoke tests, and WASM builds unless WASM is explicitly skipped.

Unix:

```bash
./qa/ci/core/check-examples.sh
```

PowerShell:

```powershell
.\qa\ci\core\check-examples.ps1
```

Use `--skip-wasm` on Unix or `-SkipWasm` on PowerShell for native-only example checks.

## Reusable browser package

The reusable browser/mobile component lives in `crates/hydra-msg-wasm`.

Build web output for another application with:

```bash
./qa/ci/core/build-wasm-web.sh
```

The generated package is written to `target/hydra-msg-wasm/web/`. Example browser hosts build their own `web/pkg/` directories only during their validation steps.
