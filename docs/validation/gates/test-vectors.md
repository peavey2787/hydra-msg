# HYDRA-MSG documentation test vectors

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Persistence vector requirements

Persistence vectors for the canonical encrypted local snapshot contract live under `qa/vectors/persistence/`. HYDRA is still pre-v1, so the current storage implementation defines the first production-candidate chunked padded envelope format. Older unpadded persistence fixtures are retained only as fail-closed regression inputs until fresh v1-candidate fixtures are frozen. Active runtime tests generate current chunked state/backup fixtures, verify chunked round trips, verify backup import/restore, and still exercise wrong-password rejection, bad-KDF-parameter rejection, ciphertext/tag mutation rejection, truncated-envelope rejection, authenticated malformed-snapshot rejection, stale-generation rollback rejection, and restore generation-floor preservation.

These vectors record KDF profile/parameters, deterministic test-only salts/nonces, ciphertext lengths through metadata artifacts, decrypted snapshot hashes when authentication is expected to succeed, expected result, and purpose. They use fixture-only passwords and deterministic test-only entropy. They must not be regenerated with production randomness.

## Cross-version compatibility vector requirements

Cross-version compatibility fixtures live under `qa/vectors/cross-version/` and are exercised by the separate QA crate `qa/tests/cross-version-compat/`. These tests are intentionally outside production crates. Because HYDRA has not shipped v1 yet, old unpadded local-state/backup fixtures fail closed; current tests generate the first production-candidate chunked fixtures at runtime until those artifacts are frozen.

The active compatibility gate covers:

- current chunked encrypted local state opens in the current runtime;
- current chunked backup imports in the current runtime;
- old unpadded persistence fixtures fail closed instead of migrating silently;
- authenticated unknown future snapshot records fail closed until a future spec explicitly supports them;
- old rollback-generation evidence still rejects stale local state;
- restoring a current backup preserves the newer local generation floor;
- packet-fragment delivery remains compatible through the public `set_packet_size`, `send`, and `receive` contract.

The current unknown-field policy is reject-by-default. Future fields require an explicit spec update and corresponding vectors before they may be accepted.

## Interop harness fixture requirements

The broader interop harness lives under `qa/tests/interop/` and is run by `qa/ci/reliability/check-interop.sh`. It consumes frozen protocol artifacts and current runtime-generated persistence artifacts while HYDRA remains pre-v1. The harness verifies fixed protocol packets, canonical header bytes, current encrypted-state fixtures, current backup fixtures, native/WASM snapshot compatibility, CLI fixture opening, and old-fixture fail-closed behavior.

`qa/fixtures/interop/manifest.sha3-256` pins protocol/static artifacts used by the harness. Updating any pinned interop fixture is a compatibility event: update the vector metadata, manifest hash, interop tests, browser probe contract, and release notes together.

## 0. Vector bundle and deterministic entropy

The frozen bundle layout is:

```text
vectors/
  manifest.sha3-256
  manifest.json
  primitive/
  handshake/
  fragment/
  ratchet/
  refresh/
  group/
  identity/
  negative/
  provenance/
```

Each vector has one canonical JSON metadata file, raw `.bin` files for every
byte string, and lowercase contiguous `.hex` mirrors. JSON contains names,
lengths, file SHA3-256 values, expected result/state, and no inline byte arrays.
Metadata JSON is UTF-8 without BOM, contains ASCII keys/values only, sorts
object keys by ASCII byte order, uses decimal integers, emits no insignificant
whitespace, and ends with one LF. Arrays retain the normative order.

The manifest sorts relative paths by raw UTF-8 byte order. Each line is:

```text
lowercase_sha3_256_hex || ASCII("  ") || relative_path || LF
```

Paths use `/`, contain no `.`/`..` segment, and are unique.

All test-only entropy is:

```text
TV_DRAW(vector_id, purpose, occurrence, length) =
  SHAKE256(
    LP(ASCII("HYDRA-MSG/test-vectors/freeze-1")) ||
    LP(ASCII(vector_id)) ||
    LP(ASCII(purpose)) ||
    u32(occurrence),
    length
  )
```

`purpose` is one of:

```text
x25519-private
mlkem-d
mlkem-z
mlkem-m
mldsa-xi
mldsa-rnd
message
nonce
commit-nonce
tree-path-secret
attachment-object-id
bootstrap-route-tag
```

Occurrence starts at zero independently for each `(vector_id, purpose)`.
Every entropy request and output length is recorded in order. Vector code must
not use production entropy. SHAKE256 here is a test-fixture expander, not a
HYDRA protocol primitive.

Complete envelopes are stored in full even when most protected plaintext is
padding. Hashes, prefixes, suffixes, or generator descriptions supplement but
never replace the raw/hex bytes.

### 0.1 Candidate evidence present

`qa/tools/vector-gen/` deterministically generates and verifies an exact
84-directory candidate matrix:

```text
primitive   2   ML-KEM and ML-DSA positive/negative primitive behavior
envelope    1   canonical protected outer header
handshake   5   INIT, RESP, hybrid KDF, confirmation/FINISH, tamper rejection
protocol    3   exact envelope, DATA, and CLOSE
negative    1   authenticated malformed protected-record matrix
ratchet    11   ordered, replay, skipped-key, gap, exhaustion, and concurrency cases
refresh     3   accepted hybrid refresh, bad signature, and concurrent-ID resolution
identity    5   rotation acceptance/rejection and device revocation
group      50   Lite/Interactive/Broadcast commits, messages, TreeKEM, and rejection cases
fragment    3   direct, lobby-scoped, and malformed fragment records
```

Every artifact has a raw `.bin` form, lowercase `.hex` mirror, SHA3-256 entry
in `manifest.sha3-256`, and JSON metadata describing entropy, result, expected
state, and cleanup. `vector_matrix.rs` rejects a missing or unexpected vector
directory, while the manifest verifier rejects inventory, ordering, hash, and
binary/hex mismatches.

`TV-HDR-000` contains the complete 64-byte canonical outer header. Executable
generator tests separately cover exact envelope-class arithmetic and malformed
header/length boundaries; those checks are not mislabeled as committed vector
directories.

The primitive candidates contain complete ML-KEM keygen/encapsulation/
decapsulation and implicit-rejection outputs plus ML-DSA keygen/sign/verify and
mutated-signature rejection outputs. They are generated by RustCrypto
`ml-kem 0.3.2` and `ml-dsa 0.1.1`. They remain single-backend candidates and
are not frozen or independently corroborated.

The handshake candidates contain complete 32,768-byte INIT and RESP envelopes,
a complete 4,096-byte authenticated FINISH envelope, transcript/KDF outputs,
X25519 and ML-KEM agreement, confirmation values, route tags, and opened FINISH
plaintext. The committed interop harness verifies the INIT/RESP signatures,
bootstrap modes/classes, responder confirmation, FINISH authentication, and
isolated tamper rejection against the current crypto/envelope runtimes.

Refresh, identity rotation/revocation, ratchet/replay, group/TreeKEM, and
fragmentation artifacts are no longer missing. The interop and crate-level
vector tests consume representative artifacts through the current runtime,
including exact-gap/replay behavior, signature rejection, group parent-state
preservation, direct/lobby fragment scope, and malformed-fragment rejection.

The remaining maturity gap is independent corroboration and freezing, not
absence of candidate coverage. `TV-HS-TAMPER-000` now commits isolated
signature, responder-confirmation, and FINISH-authentication corruption. A
normative v1 bundle still requires an independent primitive oracle, a second
protocol implementation, archived provenance, and the broader negative
handshake matrix in Section 10 covering all-zero X25519, wrong-peer identity
binding, transcript substitution, ML-KEM implicit rejection, downgrade, and
replay cases.

## 1. Envelope-class constants

```text
OUTER_HEADER_SIZE       64
AEAD_TAG_SIZE           16
INNER_HEADER_SIZE       96

class       code   envelope   body     record   max_content
Lite        01         4096    4032      4016          3920
Standard    02        32768   32704     32688         32592
Full        03       147456  147392    147376        147280

SUITE_ID ASCII  HYDRA1-MK768-M65
SUITE_ID hex    4859445241312d4d4b3736382d4d3635
```

Required arithmetic:

```text
body = envelope - 64
record = envelope - 64 - 16
max_content = envelope - 64 - 16 - 96
```

## 2. TV-HDR-000: Full protected outer header

Inputs:

```text
outer_mode      03
envelope_class  03
route_tag       000102030405060708090a0b0c0d0e0f
counter         0102030405060708
```

Expected 64 bytes:

```text
48594431010303004859445241312d4d4b3736382d4d3635
000102030405060708090a0b0c0d0e0f0102030405060708
00000000000000000000000000000000
```

Line breaks are presentation only.

## 3. TV-HDR-001: class/length rejection

Starting from TV-HDR-000, each independent mutation fails before key
selection and preserves state:

```text
byte 0 ^= 01                         InvalidMagic
byte 4 = 02                          UnsupportedVersion
byte 5 = ff                          InvalidMode
byte 6 = 00 or ff                    InvalidEnvelopeClass
byte 7 = 01                          NonZeroReserved
byte 8 ^= 01                         UnsupportedSuite
byte 48 = 01                         NonZeroReserved
class Lite, total length != 4096       InvalidEnvelopeSize
class Standard, total length != 32768  InvalidEnvelopeSize
class Full, total length != 147456     InvalidEnvelopeSize
```

Remote-visible behavior is identical.

## 4. TV-CLASS-000: deterministic class selection

For 1:1 DATA:

```text
content bytes       selected class
0..3920             Lite
3921..32592         Standard
32593..147280       Full
147281              ContentTooLarge
```

For group data with the 4-byte application length plus 3309-byte signature:

```text
application bytes   signed content bytes   smallest fitting class
0..607              app + 3313             Lite
608..29279           app + 3313             Standard
29280..143967        app + 3313             Full
143968               impossible
```

Mode constraints override the generic minimum:

```text
Interactive GROUP_DATA  Standard or Full
Broadcast GROUP_DATA    Lite, Standard, or Full
Lite GROUP_DATA         Lite exactly, application <= 607
```

## 5. TV-RATCHET-000: exact derivation

Inputs:

```text
chain_key
000102030405060708090a0b0c0d0e0f
101112131415161718191a1b1c1d1e1f

session_id
202122232425262728292a2b2c2d2e2f
303132333435363738393a3b3c3d3e3f

message_index = 7
```

Expected:

```text
message_key
57c52aff9054b2dca7612159bf8ec32f
46fba04eb3e6cc7eb41552b7472c3f28

next_chain_key
c4b16856388d565959d42e247673e502
48277624782da3160bef6a01d8bbda75

aead_key
a66e347d5219b73bdd4adcf23b5df3c
97e0b901ce59f7367e2f03eefa0620a86

aead_nonce
000000000000000000000000

route_tag
d7b4c2bd7fc3df2f141bda721c8b141f
```

`LP` and HKDF-Expand are defined in `protocol-spec.md`.

## 6. TV-ENV-000: Full protected `abc`

Use TV-RATCHET-000. Inner fields:

```text
content_kind        02 (DATA)
inner_flags         00
reserved            0000
session_id          TV-RATCHET-000 session_id
sender_id           zero[32]
epoch               0
state_version       0
message_index       7
content_len         3
content             616263
padding             zero through byte 147376
```

Outer header:

```text
48594431010303004859445241312d4d4b3736382d4d3635
d7b4c2bd7fc3df2f141bda721c8b141f0000000000000007
00000000000000000000000000000000
```

Expected:

```text
SHA3-256(protected_record)
be0e3b94445ab92d181dc929c42fc38019dbf9ffac7438d6255618c8c54cf2ce

body[0..64]
54b2cce6166b3eb6e0e1805e19c9d5629d7451dba2782efb681b768952e742e989de39d557bfb2dda9b7136fad5b26d92051a770f893d127e147c4741bce243e

body[147360..147392]
6c982f71da4ead4643235389e47b0c3b54114ab8fb038a0b85d74498102c0020

SHA3-256(body)
bf2266e5ecaf73e40433aee9b932c2a9b162534cfce92e72e9d8a330d5c26950

SHA3-256(outer_header || body)
fad5e401eea9f5b4bc1564f201d71ef6b402da5cbf0a6037c96f1e4c3f78b580
```

Successful open returns `616263`. Any one-bit mutation in class/header,
ciphertext, or tag fails.

## 7. Class-boundary records

```text
TV-ENV-LITE-MAX
  content_len = 3920 = 0x00000f50
  record[96..4016] = a5 repeated 3920
  envelope length = 4096

TV-ENV-STANDARD-MAX
  content_len = 32592 = 0x00007f50
  record[96..32688] = a5 repeated 32592
  envelope length = 32768

TV-ENV-FULL-MAX
  content_len = 147280 = 0x00023f50
  record[96..147376] = a5 repeated 147280
  envelope length = 147456
```

Each maximum has no plaintext padding. One additional byte fails locally
without consuming a send index unless the next permitted class is selected.

## 8. Authenticated inner rejection

For each class, construct a correctly authenticated ciphertext around the
mutation. AEAD succeeds, inner validation fails, and no state commits:

```text
record[1] = 01                         nonzero inner flags
record[2] = 01                         nonzero reserved
content_kind = ff                      unknown kind
content_len > class.max_content        out of bound
one byte after content is nonzero      invalid padding
inner message_index != outer counter   state mismatch
session/group ID differs               state mismatch
group mode/state version differs       state mismatch
class violates content/mode policy     state mismatch
```

## 9. Bootstrap vectors

Bootstrap requires Standard class and total length 32768:

```text
maximum generic control_len = 29359
INIT control_len = 3249
RESP control_len = 3217
INIT used body bytes = 6594
RESP used body bytes = 6562
signature length = 3309
authenticator length = 32
padding ends at Standard body byte 32704
```

Reject:

```text
Lite or Full bootstrap class
control_len = 29360
truncated signature
nonzero unused padding
nonzero INIT authenticator
inner/outer suite mismatch
wrong canonical core length
```

## 10. Required primitive/handshake vectors

```text
TV-PQ-MLKEM-000   FIPS 203 ML-KEM-768 keygen/encaps/decaps
TV-PQ-MLDSA-000   FIPS 204 ML-DSA-65 keygen/sign/verify
TV-HS-INIT-000    INIT core/digest/signature/Standard envelope
TV-HS-RESP-000    RESP core/digest/signature/transcript/Standard envelope
TV-HS-KDF-000     X25519, ML-KEM, handshake/session/confirmation keys
TV-HS-CONF-000    RESP confirmation and Lite FINISH envelope
TV-HS-ERASE-000   established state retains refresh_root, not handshake_secret
TV-HS-BAD-000     all-zero X25519 rejection
TV-HS-BAD-001     wrong expected responder fingerprint
TV-HS-BAD-002     transcript substitution
TV-HS-BAD-003     ML-KEM implicit-rejection confirmation failure
```

Each records deterministic entropy, complete public/secret test outputs,
canonical bytes, expected state transition, and cleanup expectation.

The two `TV-PQ-*` candidate directories now contain complete bytes from one
backend. They become normative only after the pinned independent runs reproduce
them and the frozen manifest incorporates them.

## 11. Ratchet/replay/refresh vectors

```text
TV-RATCHET-001 ordered receive and atomic commit
TV-RATCHET-002 authentication failure preserves chain
TV-RATCHET-003 gap of exactly 256 succeeds; delayed oldest key succeeds once
TV-RATCHET-004 gap of 257 fails without derivation
TV-RATCHET-005 skipped key succeeds once and is erased
TV-RATCHET-006 failed skipped-key AEAD does not consume key
TV-RATCHET-007 duplicate ciphertext is rejected
TV-RATCHET-008 u64 counter exhaustion closes/refreshes
TV-RATCHET-009 ambiguous send consumes index; identical retry only
TV-RATCHET-010 concurrent sends cannot reserve the same state/index
TV-REFRESH-000 signed hybrid refresh and sibling refresh-root derivation
TV-REFRESH-001 invalid INIT/RESP identity signature preserves parent state
TV-REFRESH-002 concurrent refresh IDs choose lower identifier
```

### Fragmentation vectors

```text
TV-FRAG-DIRECT-000  three canonical direct records reassemble exactly
TV-FRAG-LOBBY-000   lobby ID is explicit and retained on every part
TV-FRAG-BAD-000     zero count, bad index/count, kind, length, and trailing bytes reject
```

The fragment records are produced by an independent canonical encoder in the
isolated vector tool and consumed by `hydra-msg`'s current decoder tests. This
avoids validating the decoder solely with records produced by its own encoder.

## 12. Group-mode vectors

```text
TV-MODE-000 canonical Interactive mode policy
TV-MODE-001 canonical Broadcast presenter/audience roles
TV-MODE-002 canonical encrypted Lite policy
TV-MODE-003 invalid role for mode is rejected
TV-MODE-004 class below mode floor is rejected
TV-MODE-005 Broadcast AUDIENCE group send is rejected
TV-MODE-006 mode change replaces all membership/sender/replay secrets
TV-MODE-007 Lite rejects invalid UTF-8, attachment, and app length 608
TV-MODE-008 Interactive rejects Lite GROUP_DATA
TV-MODE-009 attachment fragment maximum is 143774 bytes
TV-MODE-010 attachment overlap, inconsistent metadata, or digest mismatch
```

## 13. TreeKEM vectors

```text
TV-TREE-000 canonical two-leaf tree hash
TV-TREE-001 deterministic node key generation from path secret
TV-TREE-002 update-path wrap/open and root agreement
TV-TREE-003 joiner cannot derive parent epoch
TV-TREE-004 removed leaf cannot decrypt update path
TV-TREE-005 public-key/tree-hash substitution is rejected
TV-TREE-006 confirmation-tag mismatch preserves parent state
TV-TREE-007 blank-node resolution canonical ordering
TV-TREE-008 fragmented update authenticates only after full reassembly
TV-TREE-009 clean self-update recovers after leaf-state snapshot
TV-TREE-010 excessive resolution/path ciphertext count is rejected
TV-TREE-011 removal resolution excludes every parent-path key known to leaf
```

## 14. Common group vectors

```text
TV-GROUP-000 canonical role/leaf-slot roster and roster_hash
TV-GROUP-001 stable commit_hash across randomized valid signatures
TV-GROUP-002 wrong parent_commit_hash enters rejection/fork handling
TV-GROUP-003 unauthorized/insufficient commit signature set
TV-GROUP-004 valid AEAD plus invalid group sender signature
TV-GROUP-005 insider AEAD forgery cannot pass sender signature
TV-GROUP-006 mode/class included in group signature digest
TV-GROUP-007 direct-wrap secret commitment mismatch
TV-GROUP-008 identity rotation atomically replaces member
TV-GROUP-009 role change refreshes epoch/sender chains
TV-GROUP-010 old mode/epoch data rejected after transition
TV-GROUP-011 leave/self-update requires the named actor signature
```

## 15. Identity vectors

```text
TV-ID-ROT-000 old/new signatures verify one digest
TV-ID-ROT-001 missing old signature is rejected
TV-ID-ROT-002 rollback rotation_index is rejected
TV-ID-ROT-003 accepted rotation closes sessions and requires new handshake
TV-ID-REV-000 authorized revocation advances roster policy
TV-ID-REV-001 revoked device cannot establish trusted session/group state
```

## 16. Freeze criterion

The vector set is complete only when:

- every ID above has concrete input and expected output bytes;
- the bundle layout, deterministic draws, exact candidate matrix, and manifests
  in Section 0 verify;
- committed runtime consumers execute the handshake, ratchet, refresh,
  identity, group-rejection, and fragmentation artifacts;
- all class, transcript, tree, commit, and KDF digests are independently
  reproduced;
- both pinned FIPS-conforming PQ backends agree and provenance proves distinct
  object code;
- two independent protocol implementations agree on complete envelopes,
  intermediate values, rejection phase, and before/after state hashes;
- the complete bundle is versioned and hashed; and
- no missing output, ambiguous encoding, or unchecked resource bound
  remains.

`release-criteria.md` records the authoritative gate status.
