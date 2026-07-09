# HYDRA-MSG specification freeze and release criteria

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

The specification is frozen only when every mandatory gate below has dated,
hashed evidence. Prose declaring success is not evidence.

## 1. Canonical documentation gate

- One canonical document set organized by authority under `docs/spec/`,
  `docs/impl/`, and `docs/validation/`. Internal roadmap notes are not
  release evidence.
- No contradictory protocol draft in the repository.
- All domain labels, enums, sizes, bounds, encodings, state transitions,
  errors, and security limits defined.
- Internal links, terminology scan, code fences, and arithmetic checks pass.
- Only release-candidate workspace crates may be treated as reference
  implementation evidence. Reserved future crate code is not conformance or
  interoperability evidence until its milestone is completed and validated.

## 2. Vector gate

- Every ID in `test-vectors.md` has complete input and expected bytes.
- INIT, RESP, FINISH, refresh, commits, welcomes, fragments, rotation, and
  revocation include complete raw envelopes, not only hashes or prefixes.
- Every negative vector names exact mutated bytes, expected rejection phase,
  and unchanged state hash.
- OpenSSL and liboqs pinned in `backend-profile.md` independently agree on all
  ML-KEM/ML-DSA primitive outputs.
- Two independent protocol implementations agree on every intermediate,
  envelope, accept/reject decision, and state transition.
- Bundle manifest and reproduction log hashes verify.

## 3. Cryptographic review gate

Independent written review covers `security-proof-sketch.md`, hybrid AKE,
refresh, signatures, TreeKEM, group governance, domain separation, entropy,
and compromise claims. Every finding has a disposition; unresolved critical
or high findings block freeze.

## 4. Backend and platform gate

The pinned backend evidence in `backend-profile.md` exists for each supported
target. KATs, exact encodings, deterministic vector APIs, constant-time claims,
unsafe/FFI audit, stack/heap scratch, failure cleanup, RNG routing, and advisory
status are recorded.

## 5. Implementation verification gate

Two independent implementations pass:

```text
complete vectors and interoperability matrix
state-machine model/concurrency tests
property and negative tests
parser/state fuzzing
sanitizers and fault injection
zeroization/log-secret tests
rollback/restart tests
resource-limit/abuse tests
```

## 6. Freeze procedure

1. Resolve all gates.
2. Assign the vector-bundle hash.
3. Record canonical documentation tree hash and source commit.
4. Obtain cryptographic and implementation reviewer sign-off.
5. Tag the freeze commit with a signed annotated tag.
6. Permit wire-affecting changes only through an incompatible suite/version
   process; editorial changes cannot alter normative behavior.

## 7. Current status

As of 2026-06-28:

| Gate | Status |
|---|---|
| canonical documentation | local structural/consistency checks passed; freeze blocked by evidence gates below |
| executable vector tooling | partial: deterministic primitive, envelope, and 1:1 handshake generator passed |
| candidate primitive vectors | partial: complete ML-KEM/ML-DSA bytes from one backend |
| first crypto adapter | local RustCrypto fixed-suite adapter passed targeted tests; pinned OpenSSL backend absent |
| 1:1 session core | M5 atomic ratchet/replay/refresh-cutover/close tests passed locally |
| complete full-protocol vectors | blocked: M4 handshake candidates exist; refresh/group/TreeKEM/identity and negative protocol generators absent |
| pinned backend reproduction | blocked: OpenSSL 3.5.7 and liboqs 0.15.0 runs absent |
| independent cryptographic review | blocked: reviewer report absent |
| backend/platform evidence | blocked: implementation measurements absent |
| two implementations/interoperability | blocked: implementations absent |

HYDRA is therefore a design specification, not a frozen standard or
production-security claim.

## 8. Local checkpoint evidence

The 2026-06-27 checkpoint recorded:

```text
PASS cargo fmt --check (isolated vector tool)
PASS cargo clippy --release --locked --offline -D warnings
PASS cargo test --release --locked --offline (isolated vector tool)
PASS two identical candidate-generation runs
PASS independent Python manifest, JSON, hex/binary, length, round-trip,
     implicit-rejection, and mutated-signature checks
PASS documentation links, code fences, domain-label inventory, stale-term
     scan, changed-file scope, and git diff whitespace check
FAIL cargo test --workspace --all-targets
```

That root-workspace failure records the state of the earlier documentation
checkpoint and is not rewritten as a pass. M1 subsequently corrected workspace
ownership to `hydra-core` and `hydra-envelope`; their targeted format, test, and
Clippy checks pass. This limited M1 evidence does not satisfy the complete
implementation-verification gate or alter any external gate above. The
isolated vector tool remains independently buildable through its own workspace
and lockfile.

The M2 envelope-vector checkpoint additionally recorded:

```text
PASS TV-HDR-000 exact documented bytes reproduced by hydra-envelope
PASS TV-HDR-001 public-field and exact class-length rejections executed
PASS Lite/Standard/Full class arithmetic executed
PASS two locked offline release generations produced an identical manifest
PASS manifest inventory, ordering, SHA3-256 hashes, and binary/hex mirrors
```

This is local reference-implementation evidence only. It does not complete
the full vector gate, PQ reproduction, independent implementation, or review
requirements.

The M3 crypto-adapter checkpoint additionally recorded:

```text
PASS SHA3-256/SHA3-512 and HMAC/HKDF known answers
PASS ChaCha20-Poly1305 round trip and authenticated mutation rejection
PASS X25519 agreement, wrong-size rejection, and all-zero rejection
PASS ML-KEM-768 key generation, encapsulation/decapsulation, and implicit rejection
PASS ML-DSA-65 randomized sign/verify and malformed-signature rejection
PASS strict public byte-size checks and fixed compile-time suite binding
PASS non-clone secret compile-fail test, targeted rustfmt, tests, and Clippy -D warnings
```

These passes cover the RustCrypto candidate adapter only. The release remains
blocked on the pinned OpenSSL/liboqs evidence, complete vectors, platform
measurements, independent implementation, and cryptographic review.

The M4 primitive-and-handshake-vector checkpoint additionally recorded:

```text
PASS complete Standard INIT and RESP candidate envelopes generated
PASS complete Lite protected FINISH candidate envelope generated and opened
PASS canonical INIT_CORE and RESP_CORE lengths and signatures checked
PASS init hash and full transcript hash recomputed
PASS both roles' X25519 and ML-KEM shared secrets matched
PASS hybrid PRK, handshake secret, session ID, confirmation, chain, and refresh-root outputs generated
PASS RESP confirmation generated and verified
PASS two release generation runs produced an identical manifest
PASS manifest inventory, ordering, SHA3-256 hashes, and binary/hex mirrors
PASS independent Python structural, metadata, transcript, HMAC, and HKDF verification
```

These are local, single-RustCrypto-backend candidate vectors. They do not
complete independent PQ reproduction, negative/full-protocol vectors, runtime
erasure evidence, platform evidence, interoperability, or review gates.

The M5 session-state checkpoint additionally recorded:

```text
PASS atomic send commits one immutable envelope and consumes one key/index
PASS ordered and bounded out-of-order receive
PASS replay and one-use skipped-key rejection
PASS gaps 255 and 256 accepted; delayed oldest key accepted once
PASS gap 257 rejected without state advancement
PASS authentication and protected-record failures preserve parent state
PASS fixed-zero nonce paired only with independently derived one-use AEAD keys
PASS confirmed refresh FINISH atomically resets session ID, chains, replay, and skipped keys
PASS invalid refresh FINISH preserves parent state; lower concurrent refresh ID wins
PASS authenticated close blocks sends and erases receiver session state
PASS targeted format, tests, and Clippy with warnings denied
```

This is local implementation evidence, not the complete M6 protocol-vector
bundle, pinned-backend evidence, interoperability evidence, or external review.
