# HYDRA lobby roundtrip

Minimal lobby flow using the public `hydra-msg` SDK.

## Navigation

- [Main README](../../README.md)
- [Examples](../README.md)
- [How HYDRA messaging works](../../docs/project/message-flow/README.md)
- [Public developer API](../../docs/project/public-developer-api.md)

## What it does

1. Alice and Bob create identities and exchange contact cards.
2. Alice and Bob establish a normal HYDRA session.
3. Alice creates a lobby and adds Bob as a member.
4. Alice creates a lobby invite and Bob joins it.
5. Alice sends a lobby message.
6. `send_lobby` returns recipient-tagged envelopes.
7. Bob receives the lobby message with normal plaintext/attachment accessors.

## Run

```bash
cargo run --manifest-path examples/lobby_roundtrip/Cargo.toml
```
