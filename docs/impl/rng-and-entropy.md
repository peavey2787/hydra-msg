# HYDRA-MSG RNG and entropy profile

All production entropy originates in the operating-system CSPRNG. Application
PRNGs, timestamps, counters, UUID generators, process IDs, and transport RNGs
are not entropy sources.

## 1. Required independent draws

| Purpose | Bytes |
|---|---:|
| X25519 private input | 32 |
| ML-KEM key generation `d` | 32 |
| ML-KEM key generation `z` | 32 |
| ML-KEM encapsulation entropy `m` | 32 |
| ML-DSA key generation seed `xi` | 32 |
| hedged ML-DSA per-signature `rnd` | 32 |
| handshake/response/refresh ID nonce | 32 |
| group commit nonce | 32 |
| TreeKEM leaf path secret | 32 |
| attachment object ID | 32 |
| bootstrap transport correlation tag | 16 |

Each table row is a separate draw. Concatenated API input such as ML-KEM
`d || z` still consists of two independently requested 32-byte values. No draw
is truncated or reused for another purpose.

## 2. API contract

```text
fill_random(destination) -> success | fatal local error
```

The call either fills the entire buffer or returns no bytes. Short reads,
fork-detection failures, unavailable providers, or health-test failures abort
the cryptographic operation without state advancement. Entropy bytes are
placed directly into zeroizing destination storage.

Approved sources are `getrandom`/`getentropy` on supported Unix targets,
`BCryptGenRandom` with system-preferred RNG on Windows, and the platform
security RNG on supported mobile targets. `/dev/urandom` file-descriptor
management is allowed only through a maintained OS abstraction.

## 3. Fork, VM, and snapshot behavior

After process fork, VM clone, resume from snapshot, or entropy-provider
reinitialization, no inherited user-space DRBG state may produce protocol
entropy. The process reopens/reseeds through the OS source before any
cryptographic operation. Deployment must ensure cloned images do not share
identity signing keys unless they represent the same intentionally replicated
device identity, which HYDRA otherwise forbids.

## 4. ML-DSA signing

Production signing uses hedged/randomized ML-DSA with a fresh 32-byte `rnd`.
Deterministic signing is permitted only in the vector harness. Failure to
obtain signing entropy fails the operation; it does not silently switch modes.
The approved backend may own this draw through its OS-seeded DRBG as specified
in `backend-profile.md`; callers need not export the resulting `rnd`.

The same rule applies to ML-KEM encapsulation entropy when the approved backend
exposes deterministic encapsulation only as a test interface.

## 5. Testing

The vector harness replaces every draw with the deterministic stream specified
in `test-vectors.md`. The deterministic provider is single-threaded, records
every request label/length/order, and is absent from production builds.

## 6. Monitoring

Metrics may count RNG failures but never contain entropy, keys, peer-controlled
buffers, or provider internal state. Repeated RNG failure makes the service
cryptographically unavailable and requires operator intervention.
