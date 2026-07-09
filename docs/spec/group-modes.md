# HYDRA-MSG group communication modes

## Navigation

- [Main README](../../README.md)
- [Spec document index](README.md)
- [Protocol spec](protocol-spec.md)
- [Threat model](threat-model.md)
- [Security proof sketch](security-proof-sketch.md)
- [State machines](state-machines.md)
- [Envelope serialization](envelope-serialization.md)
- [Chain-key evolution](chain-key-evolution.md)
- [TreeKEM profile](tree-kem.md)
- [Group modes](group-modes.md)
- [Group rekey](group-rekey.md)
- [Anonymous authorization](anonymous-authorization.md)

This document defines the authenticated communication mode stored in every
group state. A mode determines who may send, the membership-key mechanism,
per-sender state, permitted content, envelope classes, and scalability bounds.

## 1. Mode identifier

```rust
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMode {
    Interactive = 0x01,
    Broadcast = 0x02,
    Lite = 0x03,
}
```

`group_mode` is included in the creation record, every epoch commit, group
signature digest, epoch/sender-chain KDF context, welcome, and protected group
content. A mismatch is an authentication/state error. Mode is never inferred
from envelope size or UI behavior.

## 2. Common group-state fields

```text
group_id[32]
group_mode:u8
mode_policy
epoch:u64
state_version:u64
last_commit_hash[64]
roster_hash[64]
governance_policy
canonical roster
membership_key_state
sender_chain_state
replay_state
```

`state_version` increments on every accepted roster, role, policy, tree, or
mode change. `epoch` increments whenever group traffic secrets change. A commit
that changes authenticated group state increments both unless the creation
rules explicitly set both to zero.

Each roster entry has an authenticated `role`:

```text
0x01 MEMBER
0x02 PRESENTER
0x03 MODERATOR
0x04 AUDIENCE
```

Mode-specific validation rejects roles that are not permitted by that mode.
The exact active-role sets are:

```text
Interactive  MEMBER, MODERATOR
Broadcast    PRESENTER, MODERATOR, AUDIENCE
Lite         MEMBER, MODERATOR
```

Removed roster entries retain their authenticated role for archival signature
verification but are never active senders or recipients.

## 3. Interactive mode

Interactive mode is the full conversational profile.

```text
maximum roster entries        256
membership key mechanism      HYDRA TreeKEM
authorized group senders      every active MEMBER or MODERATOR
sender chains                 one per active authorized sender
group sender signature        ML-DSA-65 required per GROUP_DATA
per-sender skip bound         64
permitted envelope classes    Standard, Full
attachment content            permitted in Full
```

Interactive mode is intended for private team chats and small/medium groups
where many members may send concurrently.

Membership changes and periodic tree updates follow `tree-kem.md`. Every
authorized sender owns an independent sender-local chain. Receivers maintain
one receive chain and replay window per sender.

The deterministic envelope rule is:

- Standard for content that fits Standard;
- Full otherwise; and
- reject if the complete authenticated content does not fit Full.

Interactive mode never emits Lite group records. This avoids squeezing a
3309-byte required sender signature into a 4 KiB envelope and keeps its
workload policy unambiguous.

Rich attachment objects are fragmented at the application-content layer into
Full records. Every fragment binds object ID, total object length, fragment
index/count, media type, and a SHA3-512 whole-object digest. Fragment
reassembly is bounded and occurs only after each record authenticates.

The canonical attachment-fragment application object is defined in Section 6.

## 4. Broadcast mode

Broadcast mode is a one-to-many presenter profile.

```text
maximum roster entries        8192
maximum active presenters     16
membership key mechanism      HYDRA TreeKEM
authorized group senders      active PRESENTER or MODERATOR only
audience group sending        forbidden
sender chains                 presenters/moderators only
group sender signature        ML-DSA-65 required per GROUP_DATA
per-sender skip bound         256
permitted envelope classes    Lite, Standard, Full
attachment content            permitted for presenters in Full
```

Audience leaves receive tree updates and group data but do not own a group
send chain in conforming local state. All group recipients necessarily hold
traffic secrets sufficient to decrypt authorized senders and a malicious
recipient may misuse those secrets to construct AEAD-valid ciphertext.
Therefore role enforcement rests on the mandatory sender signature: a
GROUP_DATA record naming an AUDIENCE sender is rejected even if its AEAD
authenticates, and a signature from an audience identity is not accepted as a
presenter signature.

Audience questions, reactions requiring arbitrary text, and requests to speak
use 1:1 HYDRA sessions to a presenter/moderator. A presenter may rebroadcast an
accepted question as a new presenter-signed group object. The original 1:1
message is not implicitly converted into group authorship.

Because only a small presenter set sends:

- sender-chain/replay state is O(p), where `p <= 16`;
- ordinary audience activity causes no group-wide ratchet update;
- presenter changes require a signed role/epoch commit; and
- membership updates use the tree without giving audience members send state.

Class selection is the smallest fitting permitted class. A signed broadcast
GROUP_DATA object has these maximum application bytes:

```text
Lite         607  = 3920 - 4 - 3309
Standard   29279  = 32592 - 4 - 3309
Full      143967  = 147280 - 4 - 3309
```

The 4-byte subtraction is the application-content length inside GROUP_DATA.

## 5. Lite mode

Lite mode is an encrypted text/reaction profile. It is never plaintext.

```text
maximum roster entries        64
membership key mechanism      direct pairwise epoch wrapping
authorized group senders      every active MEMBER or MODERATOR
sender chains                 one per active authorized sender
group sender signature        ML-DSA-65 required per GROUP_DATA
per-sender skip bound         32
permitted envelope class      Lite exactly
attachment content            forbidden
```

Allowed application objects:

- canonically encoded valid UTF-8 text;
- bounded reaction objects referencing an authenticated message ID;
- delivery/read state if enabled by group policy.

Files, images, audio, arbitrary binary blobs, and application fragmentation are
forbidden. The maximum application content is 607 bytes because group sender
attribution retains the full ML-DSA-65 signature. A larger text object must be
rejected or sent through a different group whose authenticated mode permits a
larger class; it is not silently split.

Lite membership changes use the direct-wrap distribution in `group-rekey.md`.
The O(n) transition is bounded by the 64-entry limit and avoids TreeKEM public
tree/state overhead for a small text-only group.

For 1:1 DATA, which needs no per-message ML-DSA signature, a Lite envelope
carries up to 3920 content bytes.

## 6. Canonical group application objects

Every `application_content` starts with a one-byte object kind:

```text
0x01 TEXT
0x02 REACTION
0x03 DELIVERY_STATE
0x10 ATTACHMENT_FRAGMENT
```

Unknown kinds are rejected. Canonical bodies are:

```text
TEXT =
  u32(utf8_length) || utf8_bytes

REACTION =
  referenced_message_id[32] || u8(reaction_code)

DELIVERY_STATE =
  referenced_message_id[32] || u8(state_code)
```

Text is nonempty, well-formed shortest-form UTF-8 with no byte-order mark.
HYDRA does not normalize Unicode; normalization is an application display
decision and never changes authenticated bytes. Reaction and delivery codes
are fixed by the application protocol; zero and unrecognized codes are
rejected. Lite mode permits only these three kinds and applies its 607-byte
limit to the complete kind-plus-body encoding.

An object kind is accepted only when its corresponding authenticated
`content_policy_flags` bit is set. The referenced message ID is:

```text
message_id = SHA3-256(
  "HYDRA-MSG/v1/group/message-id" || suite_id ||
  group_id || group_mode || u64(epoch) || u64(state_version) ||
  sender_member_id || u64(message_index) || content_hash
)
```

`content_hash` is defined in `group-rekey.md`. References across groups or
state histories therefore do not collide under the hash assumption.

Interactive and Broadcast attachments use:

```text
ATTACHMENT_FRAGMENT =
  0x01                              // format version
  u8(flags = 0)
  u16(media_type_length, 1..64)
  object_id[32]
  u64(total_object_length)
  u32(fragment_index)
  u32(fragment_count)
  u64(fragment_offset)
  u32(fragment_length)
  whole_object_sha3_512[64]
  media_type_slot[64]
  fragment_bytes[fragment_length]
```

`media_type_slot` contains exactly `media_type_length` printable ASCII bytes
followed by zero padding. The fixed fragment header is 193 bytes including
the application-object kind. `object_id` is 32 fresh random bytes and must not
be reused for different object bytes. The hard limits are:

```text
total_object_length <= 1,073,741,824 bytes
fragment_length <= 143,774 bytes
fragment_count = ceil(total_object_length / 143,774)
fragment_offset = fragment_index * 143,774
fragment_index < fragment_count
```

The repeated whole-object digest is:

```text
whole_object_sha3_512 = SHA3-512(
  "HYDRA-MSG/v1/group/attachment-hash" || suite_id ||
  object_id || u64(total_object_length) ||
  LP(media_type_bytes) || LP(complete_object_bytes)
)
```

Every fragment except the last has exactly 143,774 bytes; the last contains
the nonzero remainder, except a positive exact multiple uses a full final
fragment. Empty attachments are rejected. All fragments repeat identical
object ID, total length, count, digest, and media type. A receiver bounds
allocation before accepting fragments, rejects overlap/duplicate conflicts,
verifies complete coverage and the whole-object digest before delivery, and
expires incomplete objects. Attachment fragments use Full envelopes only and
are forbidden in Lite mode.

## 7. Mode-policy encoding

`mode_policy` is canonical:

```text
u8(group_mode) ||
u8(minimum_envelope_class) ||
u16(max_active_senders) ||
u16(per_sender_skip_bound) ||
u16(content_policy_flags) ||
u32(max_application_object_bytes)
```

Allowed `content_policy_flags`:

```text
0x0001 UTF8_TEXT
0x0002 REACTIONS
0x0004 DELIVERY_STATE
0x0008 ATTACHMENTS
```

Unknown bits are rejected. The values must satisfy the fixed profile bounds:

| Field | Interactive | Broadcast | Lite |
|---|---:|---:|---:|
| minimum class | Standard or Full | Lite, Standard, or Full | Lite |
| max active senders | 1..256 | 1..16 | 1..64 |
| skip bound maximum | 64 | 256 | 32 |
| attachments flag | allowed | allowed | forbidden |
| maximum object bytes | 143967 | 143967 | 607 |

Policy may reduce a maximum but cannot exceed or contradict the mode profile.
If `ATTACHMENTS` is set, `max_application_object_bytes` must equal 143967 so
the canonical fragment size in Section 6 cannot vary by group.

## 8. Mode transitions

Mode is mutable only through an authorized `MODE_CHANGE` epoch commit:

1. The commit names old/new mode and exact new `mode_policy`.
2. Parent commit, epoch, state version, roster, roles, and governance are
   verified under the old mode.
3. All roles are validated under the new mode.
4. Fresh independent membership secrets are generated.
5. TreeKEM state is created/destroyed as required; no node or sender-chain key
   crosses the mode boundary.
6. New sender chains and replay state start at index zero.
7. The old mode state is erased only after atomic installation.

The mode-change commit uses the distribution mechanism of the new mode:

- entering Interactive/Broadcast installs a fresh TreeKEM tree and welcomes;
- entering Lite sends pairwise direct-wrap welcomes.

Concurrent mode changes fork like any other concurrent child commit. The group
stops application delivery until the fork is resolved.

## 9. Security and privacy effects

All modes use the same identity authentication, hybrid 1:1 channels, AEAD,
ratchet primitives, replay rules, and required group sender signatures.
“Lite” changes workload and content bounds, not confidentiality strength.

Public envelope size reveals Lite/Standard/Full. Group mode is encrypted in
ordinary group records but is known to members and may be inferred from
long-term size/sending patterns. Broadcast audience size and membership-change
fanout are not hidden.

Mode-specific authorization is checked after AEAD and before ratchet/replay
state commit. A mode or role failure is peer-visible only as a generic
authenticated group failure.

## 10. Cost summary

| Mode | Membership update | Sender state per member | Ordinary send work |
|---|---|---|---|
| Interactive | normally O(log n) on balanced dense tree; bounded resolution | O(n) receive chains | AEAD + ML-DSA |
| Broadcast | normally O(log n) on balanced dense tree; bounded resolution | O(p), `p <= 16` | Presenter: AEAD + ML-DSA; audience: none |
| Lite | O(n) pairwise wraps, `n <= 64` | O(n) receive chains | AEAD + ML-DSA |

Tree public-state synchronization may require multiple authenticated records;
cryptographic path update size follows `tree-kem.md`.
