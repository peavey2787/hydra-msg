# HYDRA-MSG v1 chain-key evolution

This document expands the normative ratchet requirements in
`protocol-spec.md`. A symmetric chain protects erased past keys; it does not
provide post-compromise security until fresh authenticated hybrid entropy is
mixed into the root.

## 1. State and invariants

Each direction owns independent state:

```text
chain_key[32]
next_index:u64
replay_window
bounded skipped_key_store
```

The initiator-to-responder and responder-to-initiator chain seeds are derived
with different labels. A chain key is never used in both directions or in two
sessions. Secret state is non-copyable, non-serializable, and zeroized on
replacement/drop.

Exactly one exclusive owner mutates each send chain. Concurrent callers are
serialized before derivation, or reserve distinct indices through one atomic
owner; two transactions MUST NOT derive from the same `(chain_key, index)`.
The same rule applies independently to every group sender chain.

`chain_key` is treated as an HKDF pseudorandom key (PRK) for HKDF-Expand. Exact
derivations for index `n` are:

```text
context = session_id || u64(n)

message_key =
  HKDF-Expand(
    chain_key,
    LP("HYDRA-MSG/v1/message-key") || LP(context),
    32
  )

next_chain_key =
  HKDF-Expand(
    chain_key,
    LP("HYDRA-MSG/v1/chain-advance") || LP(context),
    32
  )

aead_key =
  HKDF-Expand(
    message_key,
    LP("HYDRA-MSG/v1/aead-key") || LP(context),
    32
  )

aead_nonce =
  12 zero bytes

route_tag =
  HMAC-SHA3-256(
    message_key,
    "HYDRA-MSG/v1/route-tag" || session_id || u64(n)
  )[0..16]
```

Each message has a fresh one-use AEAD key, so a fixed zero nonce preserves
unique `(aead_key, nonce)` pairs. A chain state/index must never be reused, and
retransmission reuses immutable ciphertext rather than sealing again.

## 2. Atomic send

Sending is a transaction:

```text
1. From (chain_key, next_index), derive provisional message material.
2. Construct and seal exactly one envelope.
3. Hand the complete immutable envelope to the transport.
4. Commit (next_chain_key, next_index + 1).
5. Erase the old chain key and all provisional message material.
```

If step 3 has ambiguous outcome, the index MUST be treated as consumed. The
implementation may retransmit the identical immutable ciphertext, but MUST NOT
encrypt different plaintext under the old state/index.

Counter overflow at `u64::MAX` closes or refreshes the session before another
record is produced.

## 3. Atomic receive

Authentication cannot be performed without candidate message keys, so receive
ratcheting uses temporary state:

```text
1. Validate the public fixed envelope fields.
2. Copy the minimum required chain state into zeroizing temporary storage.
3. Derive no more than MAX_SKIP + 1 candidate states.
4. Match the public route tag and attempt AEAD only within that bound.
5. Validate the complete protected record and any required inner signature.
6. Commit new chain/replay/skipped state atomically.
7. Erase all temporary and unused candidates.
```

No authentication, parsing, padding, replay, epoch, or signature failure
advances persistent state.

## 4. Ordered receive

For `n == next_index`, derive exactly one candidate. On full success install
`next_chain_key` and set `next_index = n + 1`. On any failure retain the
original state.

A duplicate or older index without a stored skipped key is rejected before an
AEAD attempt when the public counter makes that determination possible. The
peer receives no distinguishable error.

## 5. Bounded out-of-order receive

Optional out-of-order mode has:

```text
MAX_SKIP = 256
maximum stored skipped keys = 256
REPLAY_WINDOW_WIDTH = MAX_SKIP + 1 = 257 positions
```

The extra replay position is required because accepting a message at
`next_index + MAX_SKIP` must retain replay state for both that current message
and all 256 preceding skipped indices. The window therefore covers the current
highest authenticated index plus the previous 256 indices. A gap of 257 is
rejected without derivation.

For `next_index < n <= next_index + MAX_SKIP`, derive candidate keys from
`next_index` through `n`. Only after message `n` fully authenticates:

- install the chain state for `n + 1`;
- retain one-use message keys for missing earlier indices;
- mark `n` accepted; and
- erase all unneeded provisional material.

For an older `n`, a matching skipped key may be used once. It is removed and
zeroized only after full authentication succeeds. Authentication failure does
not consume it, but implementations SHOULD rate-limit repeated failures to
prevent an online CPU oracle.

In particular, after authenticating index 256 from an initial
`next_index = 0`, delayed index 0 remains admissible exactly once. Its replay
is rejected after the skipped key and replay bit commit atomically.

If the gap or store bound would be exceeded, reject without derivation and use
an authenticated refresh/resynchronization flow. Chain keys are never sent.

## 6. Replay state

The replay bitmap is updated in the same atomic transaction as ratchet state.
A route-tag match is only a key-selection hint; it neither marks a replay bit
nor proves authenticity. A ciphertext may be delivered at most once.

Skipped-key entries are keyed by `(session_id, direction, index)`, not by index
alone. They are never written to crash reports, swap-backed serialization,
logs, or backups.

## 7. Security interpretation

Assuming HKDF-Expand behaves as a PRF and old secrets are erased:

```text
knowledge of chain_key[n] does not reveal chain_key[n-1] or message_key[n-1]
knowledge of message_key[n] does not reveal chain_key[n]
knowledge of chain_key[n] does reveal message_key[n] and all later chain keys
```

Therefore:

- deletion plus the one-way chain gives past-message secrecy;
- skipped keys intentionally extend the compromise window for their messages;
- a current-state compromise defeats future secrecy; and
- only the identity-signed hybrid refresh in `protocol-spec.md` can restore
  future secrecy after the attacker no longer controls the endpoint.

The protocol does not use “perfect forward secrecy” without these
qualifications.

## 8. Refresh state swap

A successful refresh derives a new refresh root, session identifier, and two
fresh direction chains. The refresh transaction commits only after both parties'
key-confirmation values authenticate. It then erases:

```text
old refresh root
old send/receive chain keys
old skipped keys and replay windows
old routing candidates
X25519 ephemeral private value and shared secret
ML-KEM decapsulation key and shared secret
all KDF and confirmation scratch values
```

Simultaneous refresh ordering and transcript fields are defined in
`protocol-spec.md`. Implementations MUST NOT mix only one component after a
nominal “hybrid refresh”: both fresh X25519 and fresh ML-KEM contributions are
required, or the refresh fails.

## 9. Minimal Rust shape

```rust
pub struct RatchetStep {
    pub message_key: MessageKey,
    pub next_chain_key: ChainKey,
    pub aead_key: AeadKey,
    pub route_tag: [u8; 16],
}

pub fn derive_step(
    chain_key: &ChainKey,
    session_id: &[u8; 32],
    index: u64,
) -> Result<RatchetStep, HydraError>;
```

`derive_step` does not mutate persistent state. Separate send/receive
transaction code commits the returned `next_chain_key` only at the points
defined above.
