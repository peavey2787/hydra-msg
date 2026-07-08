# HYDRA-MSG cryptographic backend profile

This document defines the backend contract for the reference implementation
and the independent vector oracle. Backend choice is not negotiated on wire
and cannot change any HYDRA byte.

## 1. Pinned validation backends

The freeze candidate uses two separately maintained C implementations:

| Purpose | Package | Pin | Required implementation |
|---|---|---|---|
| reference backend | OpenSSL `libcrypto` | signed tag `openssl-3.5.7` | default provider, complete HYDRA suite |
| independent vector oracle | Open Quantum Safe `liboqs` | 0.15.0 | portable ML-KEM-768 and ML-DSA-65 |

The release reference implementation calls OpenSSL through a minimal private C FFI.
It MUST NOT use an API that changes message encoding, adds an ASN.1 wrapper,
or substitutes HashML-DSA. The build lock records release archive SHA-256,
compiler, flags, target, provider, enabled CPU features, and generated binding
hash. No unpinned system library is accepted.

The OpenSSL binding exposes only the EVP interfaces needed for SHA3, HMAC,
HKDF, ChaCha20-Poly1305, X25519, ML-KEM, ML-DSA, secure cleanup, and error
disposal. It does not expose provider loading/configuration to network-facing
code. The oracle links directly to the liboqs C API; no language wrapper is
part of the normative oracle. Signed release tags, full resolved commit IDs,
source-archive hashes, build configuration, and produced library hashes are
recorded in vector provenance.

The oracle is test tooling only. Agreement is not independent when both runs
dispatch to the same object code; provenance logs must show distinct
implementations. An implementation may use another backend only after it
passes the complete frozen vector bundle and the requirements below.

The standards snapshot records FIPS 203 and FIPS 204 plus the official NIST
errata spreadsheets retrieved for the freeze. Their file hashes and retrieval
date are release artifacts. A backend interpretation inconsistent with that
snapshot blocks release.

### 1.1 Locally executed candidate backend

The repository contains an isolated candidate generator using:

```text
RustCrypto ml-kem 0.3.2
RustCrypto ml-dsa 0.1.1
rustc 1.88.0 (6b00bc388 2025-06-23)
```

It generated `qa/vectors/candidate/` and passed its internal round-trip/rejection
assertions plus manifest/hex verification. This is one implementation and is
not either pinned validation run above. It provides executable candidate
bytes, not PQ interoperability, constant-time, platform, or production-backend
evidence.

### 1.2 M3 in-repository candidate adapter

The first usable reference-code adapter is `hydra-crypto::RustCryptoBackend`.
It is fixed to `HYDRA1-MK768-M65` and exposes no runtime suite selector. Its
direct external runtime dependency pins are:

```text
sha3 0.11.0
hmac 0.13.0
hkdf 0.13.0
chacha20poly1305 0.10.1
x25519-dalek 2.0.1
ml-kem 0.3.2
ml-dsa 0.1.1
getrandom 0.4.3
rand_core 0.10.1
zeroize 1.9.0
```

This adapter uses the OS-backed `getrandom::SysRng`. ML-KEM `d` and `z` are
separate draws; encapsulation entropy and randomized ML-DSA signing entropy
are fresh per operation. Entropy failure returns before usable output. Secret
byte containers cannot be cloned or formatted and zeroize on drop. HMAC,
`x25519-dalek`, `ml-kem`, and `ml-dsa` are built with their zeroization
support enabled; ML-KEM entropy and copied shared-secret temporaries are
explicitly cleared by the adapter.

The adapter passes local known-answer, round-trip, mutation, wrong-size,
all-zero-X25519, implicit-rejection, and non-clone compile-fail tests. This
does not replace the pinned OpenSSL backend, the liboqs oracle, platform
constant-time/scratch evidence, unsafe/FFI review, or independent
interoperability evidence.

## 2. Exact primitive interfaces

Required operations:

```text
mlkem768_keygen_from_seed(seed[64]) -> ek[1184], decapsulation key state
mlkem768_encaps_from_entropy(ek[1184], m[32]) -> ct[1088], ss[32]
mlkem768_decaps(decapsulation key state, ct[1088]) -> ss[32]

mldsa65_keygen_from_seed(xi[32]) -> vk[1952], sk_backend
mldsa65_sign_digest(sk, digest[64], rnd[32], ctx = empty) -> sig[3309]
mldsa65_verify_digest(vk[1952], digest[64], sig[3309], ctx = empty) -> bool
```

ML-KEM public encodings are exactly FIPS 203 `ek` and ciphertext encodings; private decapsulation state is reconstructed from the 64-byte seed.
ML-DSA encodings are exactly FIPS 204 `vk` and signature encodings. HYDRA
signs the specified 64-byte digest as the Pure ML-DSA message with empty
context. The backend must apply the FIPS 204 message encoding internally
exactly once. Pre-hash mode, `mu` input mode, and raw test encoding are
forbidden in production.

OpenSSL parameters used by vector tooling:

```text
ML-KEM key generation: "seed" = d || z
ML-KEM encapsulation:   "ikme" = m
ML-DSA key generation:  "seed" = xi
ML-DSA signing:         "context-string" = empty
                        "test-entropy" = rnd
                        "message-encoding" = 1
                        "mu" = 0
```

The liboqs oracle installs a deterministic, single-threaded test RNG for the
same key-generation, encapsulation, and signing entropy. That RNG is forbidden
outside vector generation.

## 3. Required backend behavior

- Reject every wrong input/output length before calling the primitive.
- Treat decapsulation output as secret even for invalid ciphertext.
- Never expose implicit-rejection distinctions, internal error stacks, or
  partial secret outputs to a peer.
- Verify ML-DSA canonical encoding, including strictly increasing hint
  indices; malformed signatures fail.
- Reject an all-zero X25519 result.
- Use constant-time secret-dependent code on every supported target.
- Disable runtime dispatch to an implementation not covered by the build
  evidence.
- Zeroize caller-owned and documented backend scratch on every return path.
- Convert all remote-controlled primitive failures to one generic protocol
  failure after local rate-limited diagnostics.

## 4. Platform evidence

Each supported target has a backend evidence record containing:

```text
target triple
CPU feature policy and runtime-dispatch result
compiler and linker versions/flags
unsafe/FFI boundary inventory
stack high-water mark for every operation
heap allocation count and maximum live bytes
backend-owned scratch and cleanup behavior
constant-time claim and supporting test/tool result
KAT/vector result hash
dependency advisory scan
```

Unknown stack/scratch sizes block that target. Sanitizer, Valgrind/ctgrind
where available, and architecture-specific constant-time evidence supplement
but do not replace source review.

## 5. Startup and continuous tests

Release builds run a power-on self-test before processing peer input:

1. SHA3-256, SHA3-512, HMAC-SHA3-256, and HKDF known answers.
2. ChaCha20-Poly1305 seal/open and altered-tag rejection.
3. X25519 known answer and all-zero rejection.
4. ML-KEM deterministic keygen, encapsulation, decapsulation, and altered
   ciphertext implicit-rejection behavior.
5. ML-DSA deterministic sign/verify and malformed-signature rejection.

Failure leaves the process cryptographically unavailable. CI runs the complete
HYDRA vector bundle on every target/backend combination.

## 6. RNG boundary

Production operations obtain entropy only through the interface in
`rng-and-entropy.md`. Protocol-generated nonces, IDs, X25519 private inputs,
and ML-KEM/ML-DSA key-generation seeds are supplied explicitly by the wrapper.
OpenSSL ML-KEM production encapsulation and ML-DSA production signing use the
backend DRBG because `ikme` and `test-entropy` are test-only parameters. The
backend evidence must prove that DRBG is instantiated/reseeded from the
approved OS source and that failure is propagated. Explicit `ikme`, ML-DSA
`test-entropy`, deterministic signing, and all other test entropy parameters
are compiled behind a vector-tool-only feature that cannot be enabled in a
release artifact.

## 7. Change control

A backend update requires advisory review, source/provenance verification,
complete vector agreement, scratch/constant-time evidence renewal, and a new
backend evidence record. It does not change the protocol version or suite
unless any public byte changes; such a change is incompatible and cannot ship
under `suite_id = HYDRA1-MK768-M65`.

## 8. Authoritative references

- [NIST FIPS 203 publication and errata](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 publication and errata](https://csrc.nist.gov/pubs/fips/204/final)
- [OpenSSL 3.5 ML-KEM key interface](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)
- [OpenSSL 3.5 ML-KEM operation interface](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/)
- [OpenSSL 3.5 ML-DSA key interface](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)
- [OpenSSL 3.5 ML-DSA operation interface](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
- [liboqs 0.15.0 release](https://github.com/open-quantum-safe/liboqs/releases/tag/0.15.0)
