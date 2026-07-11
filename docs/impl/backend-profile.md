# HYDRA-MSG cryptographic backend profile

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

This document describes the cryptographic backend used by the current repository and the independent backend evidence required before a production security claim. Backend choice is not negotiated on wire and must not change any HYDRA byte.

## Current in-repository backend

The current implementation backend is `hydra_crypto::RustCryptoBackend`. It is fixed to the `HYDRA1-MK768-M65` suite and exposes no app-facing suite selector.

The current direct cryptographic dependency pins are:

```text
chacha20poly1305 = 0.10.1
getrandom = 0.4.3
hkdf = 0.13.0
hmac = 0.13.0
ml-dsa = 0.1.1
ml-kem = 0.3.2
rand_core = 0.10.1
sha3 = 0.11.0
x25519-dalek = 2.0.1
zeroize = 1.9.0
```

The backend uses OS-backed randomness through `getrandom::SysRng` where the target supports it. Secret byte containers are not cloneable through the public secret wrapper, avoid debug formatting, and zeroize on drop. The adapter performs strict input/output length checks before calling primitives and converts peer-controlled primitive failures into generic protocol failures.

Local tests cover known answers, round trips, mutation rejection, wrong-size rejection, all-zero X25519 rejection, implicit-rejection behavior, randomized ML-DSA signing, and secret-container misuse. This is strong internal implementation evidence, but it is not the same thing as external interoperability or independent cryptographic review.

## Required external backend evidence before production release

A production release must archive independent backend evidence. The recommended release evidence pair is:

| Purpose | Candidate implementation | Requirement |
|---|---|---|
| Current implementation under test | `hydra_crypto::RustCryptoBackend` | Builds from the signed source release and passes all HYDRA vectors. |
| Independent primitive/vector oracle | OpenSSL, liboqs, or another explicitly approved independent implementation | Reproduces the frozen primitive/vector bundle without sharing HYDRA object code. |

The external oracle is release evidence, not app-facing runtime code. Agreement is not independent if both runs dispatch to the same Rust object code or the same wrapped implementation. Provenance logs must record source archive hashes, exact versions, compiler/toolchain versions, flags, target triples, enabled CPU features, and produced evidence hashes.

If OpenSSL/liboqs are used for the oracle, the release evidence must record the exact pinned releases and generated vector outputs. If another independent implementation is used, the release checklist must explain why it is independent enough for the reviewed release.

## Primitive boundary

HYDRA uses the following primitive families through the backend boundary:

```text
SHA3-256 / SHA3-512
HMAC-SHA3-256
HKDF-SHA3-256
ChaCha20-Poly1305
X25519
ML-KEM-768
ML-DSA-65
```

Required backend behavior:

- reject every wrong input/output length before invoking a primitive;
- treat decapsulation output as secret even when ciphertext is invalid;
- reject all-zero X25519 shared secrets;
- avoid exposing primitive-specific peer-visible errors;
- zeroize backend-owned and documented scratch on every return path where the library gives control;
- use constant-time secret-dependent code on every supported target;
- keep deterministic/vector-only entropy paths out of production artifacts; and
- pass the frozen HYDRA vector bundle for the supported target.

## Platform evidence

Each supported target must have a backend evidence record containing:

```text
target triple
compiler and linker versions
CPU feature policy
unsafe/FFI boundary inventory, if any
stack and heap observations for high-risk operations
constant-time claim and supporting review/tool result
KAT/vector result hash
supply-chain advisory and license result
```

Unknown stack/scratch behavior, unresolved advisories, or unreviewed backend substitutions block production release for that target.

## Release status wording

Accurate current wording:

```text
HYDRA-MSG currently uses a fixed RustCrypto-based backend and has internal test evidence.
Production release still requires archived independent backend/vector evidence and external crypto/security review.
```

Do not claim that the repository currently ships an OpenSSL reference backend or liboqs oracle unless those implementations and evidence are actually present in the release artifact.
