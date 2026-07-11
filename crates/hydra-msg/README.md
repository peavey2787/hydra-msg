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
