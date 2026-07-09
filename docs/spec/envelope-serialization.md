# HYDRA-MSG envelope classes and serialization

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

This document defines the byte-exact HYDRA wire records. HYDRA has three
fixed-size envelope classes. Exact protected content length is hidden inside
each class; the selected class is public.

## 1. Envelope classes

```text
class       code   total bytes   body bytes   protected record   max content
Lite        0x01         4096         4032               4016          3920
Standard    0x02        32768        32704              32688         32592
Full        0x03       147456       147392             147376        147280
```

Every class uses:

```text
OUTER_HEADER_SIZE = 64
AEAD_TAG_SIZE = 16
INNER_HEADER_SIZE = 96

body_size(class) = envelope_size(class) - 64
protected_record_size(class) = envelope_size(class) - 64 - 16
max_content_size(class) = envelope_size(class) - 64 - 16 - 96
```

Rust constants:

```rust
pub const OUTER_HEADER_SIZE: usize = 64;
pub const AEAD_TAG_SIZE: usize = 16;
pub const INNER_HEADER_SIZE: usize = 96;

pub const LITE_ENVELOPE_SIZE: usize = 4 * 1024;       // 4,096
pub const STANDARD_ENVELOPE_SIZE: usize = 32 * 1024; // 32,768
pub const FULL_ENVELOPE_SIZE: usize = 144 * 1024;    // 147,456

pub const LITE_MAX_CONTENT_SIZE: usize = 3_920;
pub const STANDARD_MAX_CONTENT_SIZE: usize = 32_592;
pub const FULL_MAX_CONTENT_SIZE: usize = 147_280;
```

## 2. Class-selection rules

Class selection is authenticated because `envelope_class` is in the outer
header AAD. Senders MUST follow the deterministic rule for the selected
content/profile:

1. Determine the classes permitted by the content kind and active group mode.
2. Choose the smallest permitted class whose `max_content_size` contains the
   complete inner content.
3. Reject locally if no permitted class fits.

An authenticated group policy MAY set `minimum_envelope_class` to Standard or
Full as a traffic-analysis tradeoff. Such a policy still uses the smallest
permitted class at or above that floor. Arbitrary per-message promotion is
forbidden because it creates an uncontrolled metadata/covert channel.

Required class constraints:

| Content | Permitted/required class |
|---|---|
| BOOTSTRAP_INIT, BOOTSTRAP_RESP | Standard exactly |
| HANDSHAKE_FINISH, REFRESH_FINISH, CLOSE | Lite exactly |
| DATA | Smallest fitting class |
| REFRESH_INIT, REFRESH_RESP | Standard exactly |
| GROUP_DATA | Mode policy; smallest fitting permitted class |
| GROUP_COMMIT, GROUP_WELCOME | Smallest fitting Standard or Full class |
| IDENTITY_ROTATION | Standard exactly |
| DEVICE_REVOCATION | Smallest fitting Standard or Full class |

No content object may span envelopes implicitly. Objects larger than one
content capacity use an explicitly authenticated application-fragment format;
fragmentation policy is part of the content protocol, not the envelope parser.

## 3. Outer header

All integers are unsigned big-endian. Unknown modes/classes, nonzero flags, or
nonzero reserved bytes are fatal.

```text
offset  size  field
0       4     magic = ASCII "HYD1"
4       1     protocol_version = 0x01
5       1     outer_mode
6       1     envelope_class
7       1     outer_flags = 0x00
8       16    suite_id = ASCII "HYDRA1-MK768-M65"
24      16    route_tag
40      8     counter_be
48      16    reserved = all zero
64            end
```

Outer modes:

```text
0x01 BOOTSTRAP_INIT
0x02 BOOTSTRAP_RESP
0x03 PROTECTED
```

The decoder reads the first 64 bytes, validates the class, obtains the exact
required total length from the class table, and rejects any shorter or longer
record before parsing the body.

Message type, session/group ID, sender identity, group mode, group epoch,
roster/tree version, content length, and application data are encrypted inner
fields. Envelope class, outer mode, route tag, and counter are public.

For INIT and RESP, `route_tag` is a fresh random 16-byte transport correlation
value and `counter` is zero. For ordinary protected session data:

```text
route_tag = HMAC-SHA3-256(
  message_key,
  "HYDRA-MSG/v1/route-tag" || session_id || u64(message_index)
)[0..16]

counter = message_index
```

A route-tag match selects a bounded candidate; it is not authentication.
Ordered receivers SHOULD index only the next expected tag per direction.
Out-of-order mode MAY precompute tag-only candidates up to its fixed bound and
must erase provisional keys.

Initial FINISH:

```text
route_tag = HMAC-SHA3-256(
  finish_key,
  "HYDRA-MSG/v1/route-tag" || session_id || transcript_hash
)[0..16]
counter = 0
```

REFRESH_FINISH substitutes `refresh_finish_key`, `new_session_id`, and
`refresh_transcript`.

## 4. Bootstrap body

Bootstrap bodies are public signed records and always use Standard class:

```text
offset                    size       field
0                         4          control_len_be
4                         L          canonical control bytes
4+L                       3309       ML-DSA-65 signature
4+L+3309                  32         authenticator
4+L+3309+32..32704        variable   zero padding
```

The generic Standard bound is:

```text
L <= 32704 - 4 - 3309 - 32 = 29359
```

Canonical protocol values:

```text
INIT control_len = 3249
INIT used body bytes = 6594
RESP control_len = 3217
RESP used body bytes = 6562
```

For INIT, `authenticator` is all zero. For RESP, it is `resp_confirm` from
`protocol-spec.md`. The signature covers the canonical control bytes through
the mode-specific digest. Padding has no semantics and MUST be zero.

Bootstrap parsing:

1. Validate the 64-byte header, Standard class, and exact 32768-byte length.
2. Read `control_len` without allocating.
3. Check all derived offsets with checked arithmetic.
4. Scan the complete unused body tail for zero.
5. Parse the fixed canonical control structure for the selected mode.
6. Require inner/outer version and suite equality.
7. Apply trust, signature, transcript, replay, and RESP-confirmation checks.
8. Commit provisional state only after every check succeeds.

Bootstrap identity keys and public handshake material are not confidential.

## 5. Protected plaintext record

For any class:

```text
body = ChaCha20-Poly1305.Seal(
  key       = one-use aead_key,
  nonce     = 12 zero bytes,
  plaintext = protected_record[class],
  aad       = outer_header[0..64]
)
```

The fixed inner header is identical across classes:

```text
offset  size      field
0       1         content_kind
1       1         inner_flags = 0
2       2         reserved = zero
4       32        session_or_group_id
36      32        sender_id (zero for 1:1 records)
68      8         epoch_be (zero for 1:1 records)
76      8         state_version_be (zero for 1:1 records)
84      8         message_index_be
92      4         content_len_be = N
96      N         content
96+N..record_size  variable zero padding
```

Protected-record sizes:

```text
Lite       4016 bytes
Standard  32688 bytes
Full     147376 bytes
```

Allowed content kinds:

```text
0x01 HANDSHAKE_FINISH
0x02 DATA
0x03 REFRESH_INIT
0x04 REFRESH_RESP
0x05 REFRESH_FINISH
0x06 CLOSE
0x10 GROUP_COMMIT
0x11 GROUP_WELCOME
0x12 GROUP_DATA
0x20 IDENTITY_ROTATION
0x21 DEVICE_REVOCATION
```

All inner/outer flag bits are reserved and zero. Unknown content kinds,
undefined bits, nonzero padding, or content lengths beyond the authenticated
class capacity are fatal.

Inner binding:

| Kind | ID field | Sender/epoch/state-version fields |
|---|---|---|
| HANDSHAKE_FINISH | candidate session ID | zero |
| DATA, REFRESH_INIT, REFRESH_RESP, REFRESH_FINISH, CLOSE | current/candidate 1:1 session ID | zero |
| GROUP_WELCOME, IDENTITY_ROTATION, DEVICE_REVOCATION | carrying 1:1 session ID | zero |
| GROUP_COMMIT, GROUP_DATA | group ID | active sender ID and current group epoch/state version |

REFRESH_FINISH uses the candidate session ID. Group and identity objects inside
pairwise records carry and validate their own IDs, mode, and versions.

## 6. Logical types

```rust
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeClass {
    Lite = 0x01,
    Standard = 0x02,
    Full = 0x03,
}

impl EnvelopeClass {
    pub const fn envelope_size(self) -> usize {
        match self {
            Self::Lite => 4_096,
            Self::Standard => 32_768,
            Self::Full => 147_456,
        }
    }

    pub const fn max_content_size(self) -> usize {
        self.envelope_size() - 64 - 16 - 96
    }
}

pub enum OuterMode {
    BootstrapInit = 0x01,
    BootstrapResp = 0x02,
    Protected = 0x03,
}

pub struct OuterHeader {
    pub mode: OuterMode,
    pub envelope_class: EnvelopeClass,
    pub suite_id: [u8; 16],
    pub route_tag: [u8; 16],
    pub counter: u64,
}

pub struct ProtectedRecord {
    pub content_kind: u8,
    pub session_or_group_id: [u8; 32],
    pub sender_id: [u8; 32],
    pub epoch: u64,
    pub state_version: u64,
    pub message_index: u64,
    pub content: zeroize::Zeroizing<Vec<u8>>,
}

pub struct Envelope {
    pub class: EnvelopeClass,
    bytes: Box<[u8]>, // exact class size checked at construction
}
```

Decoded protected records and plaintext buffers do not implement `Debug`,
`Clone`, or serialization traits.

## 7. Header encoding

```rust
pub fn encode_outer_header(h: &OuterHeader) -> [u8; OUTER_HEADER_SIZE] {
    let mut out = [0u8; OUTER_HEADER_SIZE];
    out[0..4].copy_from_slice(b"HYD1");
    out[4] = 1;
    out[5] = h.mode as u8;
    out[6] = h.envelope_class as u8;
    out[7] = 0;
    out[8..24].copy_from_slice(&h.suite_id);
    out[24..40].copy_from_slice(&h.route_tag);
    out[40..48].copy_from_slice(&h.counter.to_be_bytes());
    // out[48..64] remains zero.
    out
}
```

Wire code uses explicit offsets and checked arithmetic, never native struct
layout, alignment, or endianness.

## 8. Protected-record construction

```rust
pub fn build_protected_record(
    class: EnvelopeClass,
    fields: &ProtectedFields,
    content: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HydraError> {
    if content.len() > class.max_content_size() {
        return Err(HydraError::ContentTooLarge);
    }

    let mut out = Zeroizing::new(vec![
        0u8;
        class.envelope_size() - OUTER_HEADER_SIZE - AEAD_TAG_SIZE
    ]);
    out[0] = fields.content_kind;
    out[1] = 0;
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..36].copy_from_slice(&fields.session_or_group_id);
    out[36..68].copy_from_slice(&fields.sender_id);
    out[68..76].copy_from_slice(&fields.epoch.to_be_bytes());
    out[76..84].copy_from_slice(&fields.state_version.to_be_bytes());
    out[84..92].copy_from_slice(&fields.message_index.to_be_bytes());
    out[92..96].copy_from_slice(&(content.len() as u32).to_be_bytes());
    out[96..96 + content.len()].copy_from_slice(content);
    Ok(out)
}
```

The unused record tail is deterministic zero padding before encryption.

## 9. Protected encoding and decoding

Encoding transaction:

1. Determine the canonical class before key derivation.
2. Derive provisional message key, next chain key, AEAD key, and route tag.
3. Build the final outer header with the selected class.
4. Build the class-sized protected record.
5. Seal once using the complete outer header as AAD.
6. Produce exactly `class.envelope_size()` immutable bytes.
7. Atomically commit the next send-chain state.
8. Erase message/AEAD/plaintext scratch material.

If output transfer is ambiguous, the index is consumed. The sender may
retransmit only the identical immutable bytes and must never seal a different
plaintext with the same one-use key.

Decoding transaction:

1. Read and validate exactly 64 header bytes.
2. Determine and enforce exact total size from the authenticated class byte.
3. Locate only a bounded candidate-key set.
4. Open AEAD into class-bounded zeroizing storage.
5. Validate inner kind, zero fields, class capacity, state binding, and the
   complete padding tail.
6. Verify required inner signatures and replay state.
7. Atomically commit ratchet/group/replay state.
8. Deliver content and erase temporary storage.

There is no separate envelope HMAC, payload hash, or outer signature.

## 10. FINISH records

HANDSHAKE_FINISH and REFRESH_FINISH are Lite protected records under their
one-use finish keys and zero nonce. HANDSHAKE_FINISH fields:

```text
content_kind        HANDSHAKE_FINISH
session_or_group_id candidate session_id
sender_id           zero
epoch               0
state_version       0
message_index       0
content             transcript_hash || session_id
```

REFRESH_FINISH substitutes the refresh key, new session ID, and refresh
transcript. Finish keys are accepted only from matching provisional state and
are erased after success or definitive abort.

## 11. Constant-work and resource rules

After class and exact total length are public, fixed-range padding/reserved
checks scan the entire class-specific range. Cryptographic comparisons use
backend constant-time operations. Parser flow may depend on public class,
version, mode, and bounded length values, but never secret data.

Implementations must not:

- allocate from an unvalidated class or content length;
- use unchecked offset arithmetic;
- decrypt into long-lived network buffers;
- expose authentication distinctions remotely;
- commit state before all inner validation; or
- retain failed plaintext/candidate keys.

Rejecting an unknown class or wrong public total length need not be
constant-time.

## 12. Byte-perfect invariants

```text
outer_header.len() == 64
body.len() == envelope_size(class) - 64
protected_record.len() == envelope_size(class) - 80
content_len <= envelope_size(class) - 176
sealed_body.len() == protected_record.len() + 16
envelope.len() == one of {4096, 32768, 147456}
outer_header[0..4] == "HYD1"
outer_header[4] == 1
outer_header[6] == envelope_class
outer_header[7] == 0
outer_header[8..24] == "HYDRA1-MK768-M65"
outer_header[48..64] == zero
protected_record[1..4] == zero
protected_record[96+content_len..record_size] == zero
bootstrap class == Standard
bootstrap unused tail == zero
```
