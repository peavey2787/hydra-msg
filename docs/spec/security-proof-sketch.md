# HYDRA-MSG security proof sketch and claim map

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

This document records the intended argument, not a machine-checked proof or
substitute for independent cryptographic review. Claims inherit the adversary
and exclusions in `threat-model.md`.

## 1. Assumptions

HYDRA assumes ML-KEM-768 IND-CCA security, X25519 CDH-style secrecy for
accepted nonzero outputs, ML-DSA-65 EUF-CMA security, SHA3 collision/preimage
resistance, HMAC/HKDF PRF security, ChaCha20-Poly1305 nonce-respecting AEAD
security, unpredictable entropy, correct trust decisions, atomic state, and
honest erasure.

## 2. Authenticated key establishment

INIT and RESP signatures bind identities, both ephemeral public contributions,
nonces, expected peer, suite, and transcript. The hybrid extract frames and
combines X25519 and ML-KEM shared secrets under the transcript. Confirmation
MACs and FINISH establish explicit agreement on transcript and session ID.

Subject to the combiner and KDF assumptions, session secrecy holds when at
least one hybrid shared-secret component remains unknown. Authentication fails
if identity trust is not established or ML-DSA is forgeable.

HYDRA performs an external domain-separated SHA3-512 hash, then supplies the
64 digest bytes as the message to Pure ML-DSA with empty context. The backend
therefore signs the FIPS 204 Pure encoding of that 64-byte message, not a raw
internal `mu` and not HashML-DSA. The attribution claim additionally depends
on collision resistance of the external digest construction.

## 3. Channel security and past-message secrecy

Each direction has an independent one-way chain. A message key and next chain
key are domain-separated; the AEAD key is used once with a fixed nonce.
Authenticated header AAD binds public class/routing/counter fields. Atomic
receive prevents chosen invalid ciphertext from advancing state.

Erasure of old chain/message/skipped keys gives past-message secrecy under KDF
one-wayness. Current chain compromise exposes current/future chain traffic
until a successful authenticated hybrid refresh; this is not continuous
post-compromise security.

## 4. Refresh recovery

Refresh signs fresh hybrid contributions and binds parent session/transcript
and chain positions. The fresh hybrid mix is extracted with the retained
refresh root, confirmed, and atomically replaces both directions.
Future-secrecy recovery requires attacker loss of endpoint access, trustworthy
identity keys, and at least one unknown fresh hybrid component. An active
attacker can block recovery.

## 5. Group authentication

All group recipients possess traffic material and can construct AEAD-valid
ciphertext. Therefore the inner ML-DSA signature, binding group/mode/policy,
epoch/state, roster, sender, index, class, and content hash, is the
authoritative sender/role attribution mechanism. It prevents attribution to an
uncompromised signing key but provides no trusted timestamp or deniability.

## 6. Group epoch and removal security

Commits bind parent, mode/mechanism, roster/tree/policy hashes, fresh nonce,
change, and key-schedule commitment under the governance/actor signature set.
Forks are detectable because distinct valid cores sharing a parent have
distinct stable commit hashes.

Lite distributes a fresh committed epoch secret through authenticated pairwise
channels. Interactive/Broadcast TreeKEM replaces the committer path, encrypts
path secrets only to canonical copath resolutions, stops using node keys known to
a removed leaf, authenticates the candidate tree hash, and confirms root
agreement. Assuming KEM security and correct filtered resolution, a removed
member cannot derive the new root from its retained parent state.

TreeKEM work is O(log n) for a balanced dense tree in the ordinary case.
Blank/unkeyed-node resolution can increase ciphertext count; exact work is
calculated first and bounded by `tree-kem.md`. HYDRA does not claim every
group update is O(log n).

## 7. Length and metadata privacy

AEAD hides content kind, identities, exact length, and padding within the
selected fixed class. Class, timing, count, direction, public counter, route
tag, endpoints, and membership fanout remain observable. Deterministic
smallest-class selection limits but does not eliminate the coarse length leak.

## 8. Composition obligations

The argument fails if keys cross purposes, a one-use key/nonce pair repeats,
parsers accept noncanonical ambiguity, failures mutate state, persistence rolls
back live chains, deterministic test entropy reaches production, or backend
encodings differ. The companion implementation profiles make these obligations
release gates.

## 9. Required external review

Before freeze, an independent reviewer must evaluate the hybrid AKE combiner,
external hashing before Pure ML-DSA, refresh recovery argument, TreeKEM path
derivation/resolution/removal, group commit/confirmation composition, and
metadata claims. Findings and dispositions are release artifacts.
