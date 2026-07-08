# WebRTC manual carrier example

This example demonstrates WebRTC as a carrier for opaque HYDRA bytes.

Important rule: **contact-card exchange is manual and out-of-band**. The page does
not send contact cards over WebRTC. Both users must copy/paste each other's
contact card first. Only after both sides have imported and verified the peer
contact card should WebRTC carry HYDRA handshake bytes and encrypted envelopes.

## Build WASM

From the repo root:

```powershell
examples\webrtc_manual_carrier\scripts\build-wasm.ps1
```

or:

```bash
examples/webrtc_manual_carrier/scripts/build-wasm.sh
```

## Run

```bash
cargo run --release --manifest-path examples/webrtc_manual_carrier/Cargo.toml -- 0.0.0.0:8789
```

Open the printed LAN URL from two browser tabs or two devices.

## Flow

1. On both devices, click **Create local HYDRA identity/contact card**.
2. Manually copy each contact card to the other device using any out-of-band
   method: QR, text file, chat, clipboard, or in-person transfer.
3. Paste the peer contact card and click **Import peer contact card**.
4. Compare/confirm the safety code, then click **Verify imported contact**.
5. Use the WebRTC manual SDP offer/answer text boxes to open a DataChannel.
6. The initiator sends the HYDRA handshake offer over the DataChannel.
7. The responder replies with the HYDRA handshake answer over the DataChannel.
8. Both sides can send encrypted HYDRA messages over WebRTC.

WebRTC, SDP copy/paste, and the DataChannel are carrier mechanics only. HYDRA
identity, contact trust, handshake, encryption, decryption, and message parsing
stay inside the `hydra-msg` facade.
