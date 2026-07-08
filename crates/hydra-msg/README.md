# hydra-msg

`hydra-msg` is the stupid-simple public developer facade for HYDRA-MSG.

Apps should start here instead of depending on low-level crypto, envelope,
session, group, or demo app crates directly.

```rust
use hydra_msg::{Hydra, HydraMessage};

let mut hydra = Hydra::open("./hydra-msg-data")?;
let my_id = hydra.generate_id("password")?;
hydra.set_active_id(my_id, "password")?;

let bob = hydra.add_contact(bob_card)?;
let offer = hydra.init_handshake(bob.id())?;
let answer = hydra.reply_handshake(offer)?;
hydra.finish_handshake(answer)?;

let envelope = hydra.send(
    bob.id(),
    HydraMessage::text("hello").attach_bytes("data.bin", bytes_here)?,
)?;
let data = hydra.receive(envelope)?;
```

Carriers such as WebRTC, files, HTTP, QR codes, relays, libp2p, Kaspa
pointers, and mailboxes only move the opaque bytes from this crate.

Source of truth for the target API:

```text
../../docs/project/public-developer-api.md
```


## P4 storage behavior

`Hydra::open(path)` creates/loads a native filesystem store at `path`.
Identity seed material is encrypted at rest and identities reopen locked by default.
Contacts, message history, attachments, lobby summaries, and local counters are
persisted by the facade. Full backups are encrypted/authenticated with the backup
password and restore the local HYDRA state.
