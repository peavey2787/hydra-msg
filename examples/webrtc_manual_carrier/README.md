# WebRTC manual carrier example

Demonstrates WebRTC DataChannel as a carrier for opaque HYDRA bytes.

Contact-card exchange is manual and out-of-band. The page does not send contact cards over WebRTC. Both users copy/paste each other's contact card first. WebRTC carries HYDRA handshake bytes and encrypted envelopes after both users import and verify the peer contact card.

## Navigation

- [Main README](../../README.md)
- [Examples](../README.md)
- [WASM/JavaScript bindings](../../crates/hydra-msg-wasm/README.md)
- [Carrier example rules](../../docs/project/carrier-examples.md)

## Build example-local WASM

Unix:

```bash
examples/webrtc_manual_carrier/scripts/build-wasm.sh
```

PowerShell:

```powershell
examples\webrtc_manual_carrier\scripts\build-wasm.ps1
```

This writes the example package to:

```text
examples/webrtc_manual_carrier/web/pkg/
```

For a reusable package for your own app, use `qa/ci/build-wasm-web.sh` or `qa/ci/build-wasm-web.ps1`; that output goes to `target/hydra-msg-wasm/web/`.

## Run

```bash
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

Open the printed LAN URL from two browser tabs or two devices.

## Flow

1. On both devices, create a local HYDRA identity/contact card.
2. Manually copy each contact card to the other device using QR, text file, chat, clipboard, or in-person transfer.
3. Paste the peer contact card and import it.
4. Compare and confirm the safety code.
5. Use the WebRTC manual SDP offer/answer text boxes to open a DataChannel.
6. The initiator sends the HYDRA handshake offer over the DataChannel.
7. The responder replies with the HYDRA handshake answer over the DataChannel.
8. Both sides send encrypted HYDRA messages over WebRTC.
