# HYDRA-MSG interoperability profile

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

This document defines cross-implementation behavior not left to host language,
platform, or transport convention.

## 1. Canonical bytes

- Integers are unsigned big-endian and fixed-width.
- `LP(x)` is `u32(len(x)) || x`; lengths count bytes.
- Text is shortest-form UTF-8, no BOM, and is not Unicode-normalized.
- Lists use specified canonical order; duplicates are rejected.
- Optional data is represented only by an explicit flag/length defined by the
  owning structure.
- Reserved bytes/bits and unused fixed slots are zero.
- No trailing bytes are accepted.
- Native structs, JSON, CBOR, ASN.1, protobuf, and platform key containers are
  never wire encodings unless a structure explicitly says so.

## 2. Cryptographic encodings

X25519 uses RFC 7748 32-byte little-endian u-coordinate encodings at the
primitive boundary. ML-KEM and ML-DSA use exact FIPS 203/204 public encodings.
HYDRA hashes and transmits those opaque byte strings unchanged.

SHA3/HMAC/HKDF outputs are raw bytes. ML-DSA signs the exact 64-byte digest as
Pure ML-DSA with empty context. ChaCha20-Poly1305 output is ciphertext followed
by its 16-byte tag.

## 3. Record transport

The receiver reads 64 bytes, validates the public header, obtains the exact
class size, then reads exactly the remaining bytes. EOF, timeout, overlong
record, or coalesced transport data never changes the record boundary.
Datagram transports carry exactly one envelope per datagram or define a
separate authenticated framing layer.

## 4. Deterministic choices

Senders choose the smallest fitting class allowed by content and authenticated
mode policy. Lists, signatures, fragments, tree nodes, and resolution targets
use their specified canonical order. Implementations cannot make a locally
reasonable alternative choice and remain interoperable.

## 5. Error behavior

Local APIs return typed errors; wire peers receive only the protocol-defined
generic failure or silence. Rejecting an invalid object never changes
persistent state. Implementations agree on accept/reject and resulting state,
not on local error strings.

## 6. Vector bundle

The frozen vector bundle contains:

```text
manifest with schema version and file SHA3-256 values
input entropy/request transcript
complete canonical intermediate objects
complete envelopes as raw binary plus lowercase hex
expected accept/reject and before/after state hashes
backend provenance and reproduction commands
```

Binary and hex forms must decode identically. A vector is accepted only when
the two pinned backends independently produce the listed primitive outputs and
two complete protocol implementations produce every protocol/state result.

`qa/vectors/candidate/` is explicitly outside the frozen bundle until those
conditions hold. Candidate provenance may name one backend and must never be
presented as interoperability evidence.

## 7. Interoperability matrix

Before freeze, tests cover both send directions for every pair of independent
implementations on little- and big-endian hosts where available, 32/64-bit
targets, and fragmented/coalesced stream delivery. Every negative vector must
be rejected without state divergence.
