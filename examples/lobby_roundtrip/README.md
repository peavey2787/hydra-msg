# HYDRA lobby roundtrip

Minimal lobby flow using only the public `hydra-msg` facade:

1. Alice and Bob create identities and exchange contact cards.
2. Alice and Bob establish a normal HYDRA session.
3. Alice creates a lobby and adds Bob as a member.
4. Alice creates a lobby invite and Bob joins it.
5. Alice sends a lobby message.
6. `send_lobby` returns recipient-tagged envelopes so the app knows who to deliver each opaque envelope to.
7. Bob receives the lobby message and gets normal plaintext/attachment accessors.

Run from the repo root:

```bash
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
```
