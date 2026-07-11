# HYDRA-MSG abuse and resource-limit profile

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)
- [Anonymous authorization](../spec/anonymous-authorization.md)

Availability is not a cryptographic guarantee. HYDRA-MSG nevertheless bounds attacker-controlled work before allocation-heavy parsing, public-key operations, or state mutation whenever the facade can enforce that ordering.

## Facade safety ceilings

`crates/hydra-msg/src/limits.rs` is the source of truth. Current facade ceilings include:

| Resource | Current ceiling |
|---|---:|
| encrypted local-state container | `MAX_STATE_SNAPSHOT_BYTES * 2 + 512 KiB` |
| encrypted backup container | `MAX_STATE_SNAPSHOT_BYTES * 2 + 512 KiB` |
| authenticated plaintext snapshot | 64 MiB |
| identities | 256 |
| contacts | 1,024 |
| lobbies | 256 |
| stored messages | 100,000 total; 10,000/contact |
| stored message bytes | 256 MiB total; 64 MiB/contact |
| message plaintext | 4 MiB |
| attachments | 16/message |
| attachment bytes | 16 MiB/attachment |
| attachment filename | 255 bytes |
| encoded message payload | 32 MiB |
| handshake offer/answer | 16 KiB each |
| pending handshakes | 64; 10-minute age |
| anonymous-auth token | 4 KiB |
| spent anonymous-auth nullifiers | 100,000 |
| pending fragment parts | 16,384 global |
| fragments per logical message | 16,384 |
| incomplete messages | 128 global; 8/contact; 8/lobby |
| pending fragment bytes | 64 MiB |
| fragment age | 10 minutes |
| lobby outbound packets | 4,096 |
| lobby outbound envelope bytes | 64 MiB |

The code also has lower-level protocol bounds in `hydra-core`, `hydra-session`, and `hydra-group`. Those are protocol invariants. The facade ceilings above are the app-facing resource-exhaustion boundary.

## Pre-authentication controls outside the SDK

Apps and carriers still need their own finite controls for:

```text
open transports and partial records
bytes buffered by the carrier
handshake attempts per peer/source/account
delivery retries and mailbox polling
failed authentication attempts
log and diagnostic volume
```

The SDK prevents one API call from demanding unbounded parser/state-machine work. It does not prevent an attacker from saturating a network, relay, mailbox, database, or application account unless the app/carrier applies finite rate limits.

## Work ordering

HYDRA should reject hostile input in this order whenever possible:

1. public byte length and framing checks;
2. magic/version/suite/class/reserved checks;
3. finite resource admission;
4. bounded route/state lookup;
5. AEAD, signature, or KEM work only after cheap checks pass;
6. canonical protected-object and policy validation; and
7. atomic state commit.

## Fragment defenses

Fragments are retained sparsely and bounded by authenticated owner/lobby scope. Duplicate conflicts discard the incomplete message. Stale fragments expire. Deleting a contact or closing a lobby removes or ignores stale pending work. No partial message reaches application code.

## Authenticated abuse

A valid peer can still consume storage and bandwidth. Apps should apply user/account quotas, message retention policy, attachment policy, moderation, and backup UX. Cryptographic validity is not authorization to consume unlimited resources.

## Failure privacy

Peer-visible behavior should avoid distinguishing parse, trust, replay, signature, KEM, AEAD, quota, and policy failure when that distinction would create an oracle. Local diagnostics should use coarse categories and avoid peer-controlled high-cardinality labels.
