# HYDRA handshake roundtrip

Minimal two-device-style flow using only the public `hydra-msg` facade:

1. Alice and Bob open local HYDRA stores.
2. Each generates an identity.
3. They exchange contact cards over an imaginary carrier.
4. Alice creates a handshake offer.
5. Bob replies.
6. Alice finishes the handshake.
7. Alice sends an encrypted message.
8. Bob receives plaintext.

Run from the repo root:

```bash
cargo run --manifest-path examples/handshake_roundtrip/Cargo.toml
```
