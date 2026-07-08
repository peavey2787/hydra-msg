# hydra-msg

`hydra-msg` is the Rust SDK facade for HYDRA-MSG.

Apps should start here instead of depending directly on crypto, envelope, session, group, carrier, or demo code.

## Navigation

- [Main README](../../README.md)
- [Crates](../README.md)
- [WASM/JavaScript bindings](../hydra-msg-wasm/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../../docs/project/public-developer-api.md)

## Small working shape

```rust
use hydra_msg::{Hydra, HydraMessage};

let mut hydra = Hydra::open("./hydra-msg-data")?;
let my_id = hydra.generate_id("password")?;
hydra.set_active_id(my_id, "password")?;

let peer = hydra.add_contact(peer_contact_card)?;
let answer = peer_device.reply_handshake(hydra.init_handshake(peer.id())?)?;
hydra.finish_handshake(answer)?;

let envelope = hydra.send(peer.id(), HydraMessage::text("hello"))?;
let data = peer_device.receive(envelope)?;
println!("{}", data.text()?);
```

For a complete runnable version, use:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
```

## Carrier rule

Carriers such as WebRTC, files, HTTP, QR codes, relays, libp2p, Kaspa pointers, and mailboxes only move opaque bytes produced by this crate.

HYDRA identity, contact trust, handshakes, sessions, encryption, decryption, attachments, lobbies, backup, and local storage stay inside the facade.

## Native storage

`Hydra::open(path)` creates or loads a native filesystem store at `path`.

Identity seed material is encrypted at rest. Identities reopen locked by default. Contacts, message history, attachments, lobby summaries, and local counters are persisted by the facade. Backups are encrypted and authenticated with the backup password.
