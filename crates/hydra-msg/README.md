# hydra-msg

`hydra-msg` is the main Rust SDK for HYDRA-MSG apps.

Apps should start here instead of depending directly on crypto, envelope, session, group, carrier, or example code.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)

## Small app shape

```rust
use hydra_msg::{Hydra, HydraMessage};

let mut hydra = Hydra::open("./hydra-msg-data", "state-password")?;
let my_id = hydra.generate_id("password")?;
hydra.set_active_id(my_id, "password")?;

let peer = hydra.add_contact(peer_contact_card)?;
let offer = hydra.init_handshake(peer.id())?;
app_send_to_peer(offer.as_bytes())?;
let answer = app_wait_for_peer_answer()?;
hydra.finish_handshake(answer)?;

let packets = hydra.send(peer.id(), HydraMessage::text("hello"))?;
for packet in packets {
    app_send_to_peer(packet.as_bytes())?;
}
```

For the full two-device explanation, see [How HYDRA messaging works](../../docs/impl/message-flow/README.md).

## Session security cadence

Every encrypted envelope advances a one-way ratchet and erases old message
material. Apps that also want periodic fresh hybrid session material can set a
per-contact interval or `HydraSessionSecurityPolicy`. For example,
`set_session_refresh_interval(contact_id, 1)` permits one outbound logical
message and then makes the next send return `SessionRefreshRequired` until the app completes
`begin_session_refresh` / `reply_session_refresh` / `finish_session_refresh`
over its carrier. This is an explicit peer round trip and conditional
post-compromise recovery, not automatic healing during an ongoing endpoint
compromise. Each peer configures and counts its own outbound direction
independently.

For runnable code, use:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
```

## Carrier rule

Carriers such as WebRTC, files, HTTP, QR codes, relays, libp2p, Kaspa pointers, and mailboxes only move opaque bytes produced by this crate.

HYDRA identity, contact trust, handshakes, sessions, encryption, decryption, attachments, lobbies, backup, and local storage stay inside the SDK.

## Native storage

`Hydra::open(path, state_password)` creates or loads an authenticated-encrypted native filesystem store at `path`.

Identity seed material is encrypted at rest. Identities reopen locked by default. Contacts, message history, attachments, lobby summaries, and local counters are stored inside `state.hydra`. Backups are encrypted and authenticated with the backup password.
