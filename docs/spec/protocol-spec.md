# RFC: HYDRA-MSG v1

## Navigation

- [Main README](../../README.md)
- [Spec docs](README.md)
- [Protocol spec](protocol-spec.md)
- [Threat model](threat-model.md)
- [Public developer API](public-developer-api.md)
- [How HYDRA messaging works](../impl/message-flow/README.md)

## Hybrid post-quantum secure messaging protocol

Status: design specification. The wire format is frozen only after the required
test vectors in `test-vectors.md` contain complete byte strings and pass two
independent implementations. This document uses the key words MUST, MUST NOT,
REQUIRED, SHOULD, SHOULD NOT, and MAY as normative requirements.

## 1. Goals and non-goals

HYDRA-MSG provides:

- mutually authenticated, hybrid X25519 + ML-KEM-768 session establishment;
- post-quantum confidentiality against store-now-decrypt-later adversaries;
- post-quantum identity authentication with ML-DSA-65;
- past-message secrecy after old keys are erased;
- explicit key confirmation;
- Lite (4 KiB), Standard (32 KiB), and Full (144 KiB) fixed-size records with
  encrypted message type, identities, group metadata, exact content length,
  and padding;
- authenticated Interactive, Broadcast, and Lite group modes; and
- bounded replay and out-of-order processing.

The normal HYDRA-MSG message path is key/session based. v1 does not itself
provide network anonymity, relay anonymity, availability, deniability, endpoint
security, protection from traffic timing/volume analysis, or recovery from a
compromised identity key. Apps may create anonymous-to-peer or unlinkable chat
flows with fresh one-time identities and contact cards, but bootstrap records
still expose the public keys used for that chat to any observer who can see
those records. An identity-hiding prekey mode is out of scope for v1 and MUST
NOT be claimed by an implementation.

The normative adversary model, trust assumptions, compromise cases, and claim
boundaries are defined in `threat-model.md`. Security claims in this document
MUST be interpreted together with that file.

The consolidated state-transition authority is `state-machines.md`.
`backend-profile.md`, `rng-and-entropy.md`, `interop-profile.md`,
`persistence-and-rollback.md`, `implementation-hardening.md`, and
`abuse-and-rate-limits.md` are normative implementation profiles.
`security-proof-sketch.md` maps the claims to their assumptions, while
`release-criteria.md` alone determines freeze status.

“Forward secrecy” in this specification means secrecy of messages protected by
erased message and chain keys. It does not mean that compromise of the current
chain state leaves future traffic secure. Future secrecy resumes only after an
authenticated hybrid refresh contributes fresh X25519 and ML-KEM secrets.

## 2. Cryptographic suite

The only v1 suite is the following 16-byte value:

```text
suite_id = ASCII("HYDRA1-MK768-M65") = 16 bytes
```

The suite binds:

```text
KEM:        ML-KEM-768, FIPS 203
DH:         X25519, RFC 7748
Signature:  ML-DSA-65, FIPS 204
KDF:        HKDF-HMAC-SHA3-256, RFC 5869 construction
Hash:       SHA3-256; SHA3-512 for signature transcript digests
AEAD:       ChaCha20-Poly1305, RFC 8439
```

Pinned protocol byte sizes:

```text
ML-KEM-768 encapsulation key     1184
ML-KEM-768 ciphertext            1088
ML-KEM-768 shared secret           32
ML-DSA-65 verification key       1952
ML-DSA-65 signature              3309
X25519 public/private value        32
ChaCha20-Poly1305 key              32
ChaCha20-Poly1305 nonce            12
ChaCha20-Poly1305 tag              16
SHA3-256 output                    32
SHA3-512 output                    64
```

Private ML-KEM/ML-DSA key representation is backend-internal and not a wire
constant. Expanded FIPS encodings, approved seed representations, and
non-exportable HSM handles are all acceptable if operations and public outputs
conform exactly.

The suite identifiers and byte encodings above are exact. A different
primitive, parameter set, encoding, or byte size is a different suite;
negotiation inside an unauthenticated handshake is forbidden.

An implementation MUST use a maintained constant-time cryptographic backend,
run its backend known-answer tests at build or startup, use an approved OS
CSPRNG, reject an all-zero X25519 result, and fail closed on any primitive or
length mismatch. Implementations follow the current official errata for the
pinned NIST publications without changing wire encodings; any erratum that
changes interoperability requires a new suite identifier. Secret-dependent
diagnostics MUST NOT cross a trust boundary.

## 3. Encoding and domain separation

All integers are unsigned big-endian. `u16(x)`, `u32(x)`, and `u64(x)` denote
fixed-width encodings. `LP(x)` denotes `u32(len(x)) || x`. Concatenations in
this specification are unambiguous because every component is fixed-width or
length-prefixed.

Domain labels are exact ASCII bytes. Labels are never NUL-terminated:

```text
HYDRA-MSG/v1/fingerprint
HYDRA-MSG/v1/init-signature
HYDRA-MSG/v1/resp-signature
HYDRA-MSG/v1/transcript
HYDRA-MSG/v1/root-key
HYDRA-MSG/v1/refresh-root
HYDRA-MSG/v1/session-id
HYDRA-MSG/v1/confirm-key
HYDRA-MSG/v1/resp-confirm
HYDRA-MSG/v1/finish-key
HYDRA-MSG/v1/init-chain/i2r
HYDRA-MSG/v1/init-chain/r2i
HYDRA-MSG/v1/message-key
HYDRA-MSG/v1/chain-advance
HYDRA-MSG/v1/aead-key
HYDRA-MSG/v1/route-tag
HYDRA-MSG/v1/refresh
HYDRA-MSG/v1/refresh-init-signature
HYDRA-MSG/v1/refresh-resp-signature
HYDRA-MSG/v1/group/commit-signature
HYDRA-MSG/v1/group/member-id
HYDRA-MSG/v1/group/roster-hash
HYDRA-MSG/v1/group/policy-hash
HYDRA-MSG/v1/group/change-hash
HYDRA-MSG/v1/group/commit-hash
HYDRA-MSG/v1/group/epoch-secret-commitment
HYDRA-MSG/v1/group/mode-policy-hash
HYDRA-MSG/v1/group/epoch
HYDRA-MSG/v1/group/chain
HYDRA-MSG/v1/group/content-hash
HYDRA-MSG/v1/group/message-signature
HYDRA-MSG/v1/group/message-id
HYDRA-MSG/v1/group/attachment-hash
HYDRA-MSG/v1/group/commit-object-hash
HYDRA-MSG/v1/group/tree/path
HYDRA-MSG/v1/group/tree/node-seed
HYDRA-MSG/v1/group/tree/node-hash
HYDRA-MSG/v1/group/tree/tree-hash
HYDRA-MSG/v1/group/tree/wrap-salt
HYDRA-MSG/v1/group/tree/wrap-key
HYDRA-MSG/v1/group/tree/confirmation
HYDRA-MSG/v1/group/tree/root
HYDRA-MSG/v1/group/tree/commitment
HYDRA-MSG/v1/group/tree/update-path-hash
HYDRA-MSG/v1/identity-rotation
HYDRA-MSG/v1/device-revocation
HYDRA-MSG/v1/storage/public-state-hash
```

HKDF is always written as:

```text
PRK = HKDF-Extract(salt, IKM)
OKM = HKDF-Expand(PRK, LP(label) || LP(context), length)
```

Callers MUST NOT reverse the `salt` and `IKM` arguments. A label is part of
`info`, never a salt. Raw concatenation of independently generated shared
secrets MUST be framed:

```text
hybrid_ikm = LP(x25519_secret) || LP(mlkem_secret)
```

## 4. Identity

Every device has an independent ML-DSA-65 keypair. Secret identity keys MUST
NOT be shared between devices.

```text
device_fingerprint =
  SHA3-256("HYDRA-MSG/v1/fingerprint" || suite_id || verification_key)
```

The application MUST authenticate a device fingerprint out of band, through a
verified account/device roster, or through an explicit trust-on-first-use
policy that visibly reports later changes. The protocol does not turn an
unverified public key into a verified human identity.

ML-DSA signatures in v1 sign the 64-byte SHA3-512 digest specified at each call
site. The FIPS 204 context string is empty because the signed digest already
contains a mandatory HYDRA domain label and `suite_id`. Both deterministic and
hedged/randomized conforming ML-DSA signing are accepted. Verifiers require the
exact 3309-byte signature encoding. The backend operation is pure ML-DSA on
those 64 digest bytes, not the separately encoded HashML-DSA interface; mixing
the two is an interoperability failure.

## 5. Session establishment

### 5.1 State machine

```text
Initiator: New -> InitSent -> RespVerified -> FinishSent -> Established
Responder: New -> InitVerified -> RespSent -> FinishVerified -> Established
Either:    * -> Closing -> Closed
```

No application data may be sent before `Established`. The initiator may enter
`Established` immediately after sending a valid FINISH; delivery of FINISH is
not guaranteed. A later authenticated peer response provides liveness, not an
additional cryptographic property.

Each handshake uses fresh X25519 and ML-KEM keypairs. Ephemeral secret material
MUST be erased after the handshake and confirmation secrets are derived. A
nonce is 32 unpredictable CSPRNG bytes and MUST NOT be reused by the same
identity.
Retransmission reuses the identical immutable INIT or RESP bytes; an endpoint
MUST NOT regenerate a randomized signature, nonce, key, or ciphertext within
one handshake instance.

### 5.2 INIT

The initiator generates an ephemeral X25519 keypair and an ephemeral ML-KEM-768
keypair. `INIT_CORE` is:

```text
u8(protocol_version = 1) ||
suite_id ||
init_nonce[32] ||
expected_responder_fingerprint[32] ||
initiator_identity_verification_key[1952] ||
initiator_x25519_ephemeral_public[32] ||
initiator_mlkem_encapsulation_key[1184]
```

`INIT_CORE` is exactly 3249 bytes.

The initiator signs:

```text
init_sig_digest =
  SHA3-512(
    "HYDRA-MSG/v1/init-signature" ||
    suite_id ||
    LP(INIT_CORE)
  )

init_signature = ML-DSA-65.Sign(initiator_identity_signing_key, init_sig_digest)
```

The INIT bootstrap control bytes are `INIT_CORE`; `init_signature` occupies
the fixed bootstrap signature field defined in `envelope-serialization.md`.
The responder MUST verify the expected responder fingerprint, suite, nonce
policy, initiator trust policy, and signature before performing KEM
encapsulation.

Responders maintain a bounded, expiring cache of accepted
`(initiator_fingerprint, init_nonce, init_hash)` tuples. An exact replay is
rejected or receives the identical cached immutable RESP; it MUST NOT create a
second session. Cache expiry is deployment policy, so rate limiting remains
required and replay resistance across responder state loss is not claimed.

```text
init_hash =
  SHA3-512("HYDRA-MSG/v1/transcript" || LP(INIT_CORE || init_signature))
```

### 5.3 RESP

The responder generates a fresh X25519 keypair and nonce, encapsulates to the
initiator's ephemeral ML-KEM encapsulation key, and forms:

```text
RESP_CORE =
  u8(protocol_version = 1) ||
  suite_id ||
  init_hash[64] ||
  resp_nonce[32] ||
  initiator_fingerprint[32] ||
  responder_identity_verification_key[1952] ||
  responder_x25519_ephemeral_public[32] ||
  mlkem_ciphertext[1088]
```

`RESP_CORE` is exactly 3217 bytes.

The responder computes the hybrid secret before signing:

```text
x_secret = X25519(responder_x25519_secret,
                  initiator_x25519_ephemeral_public)
```

An all-zero `x_secret` is a fatal handshake error.

```text
resp_sig_digest =
  SHA3-512(
    "HYDRA-MSG/v1/resp-signature" ||
    suite_id ||
    init_hash ||
    LP(RESP_CORE)
  )

resp_signature = ML-DSA-65.Sign(responder_identity_signing_key, resp_sig_digest)

transcript_hash =
  SHA3-512(
    "HYDRA-MSG/v1/transcript" ||
    LP(INIT_CORE || init_signature) ||
    LP(RESP_CORE || resp_signature)
  )
```

Both sides derive:

```text
hybrid_prk =
  HKDF-Extract(
    salt = transcript_hash,
    IKM  = LP(x_secret) || LP(mlkem_shared_secret)
  )

handshake_secret =
  HKDF-Expand(
    hybrid_prk,
    LP("HYDRA-MSG/v1/root-key") || LP(transcript_hash),
    32
  )

session_id =
  HKDF-Expand(
    handshake_secret,
    LP("HYDRA-MSG/v1/session-id") || LP(transcript_hash),
    32
  )

confirm_key =
  HKDF-Expand(
    handshake_secret,
    LP("HYDRA-MSG/v1/confirm-key") || LP(transcript_hash),
    32
  )
```

RESP carries this 32-byte authenticator after its signature:

```text
resp_confirm =
  HMAC-SHA3-256(
    confirm_key,
    "HYDRA-MSG/v1/resp-confirm" || transcript_hash || session_id
  )
```

The initiator MUST verify the responder fingerprint and trust policy, RESP
signature, echoed initiator fingerprint, ML-KEM decapsulation result, all-zero
X25519 rule, derived `session_id`, and `resp_confirm`. Any failure erases
provisional state.

### 5.4 FINISH and chain initialization

FINISH is a one-use protected record encrypted under:

```text
finish_key =
  HKDF-Expand(
    handshake_secret,
    LP("HYDRA-MSG/v1/finish-key") || LP(transcript_hash),
    32
  )
finish_nonce = 12 zero bytes
```

Zero is safe only because `finish_key` is unique to one handshake and MUST be
used exactly once. FINISH contains `transcript_hash || session_id`. Its outer
header is AEAD AAD. The responder becomes established only after successful
FINISH authentication and exact transcript/session matching.

After FINISH, derive direction chains:

```text
chain_i2r = HKDF-Expand(handshake_secret,
  LP("HYDRA-MSG/v1/init-chain/i2r") || LP(transcript_hash), 32)

chain_r2i = HKDF-Expand(handshake_secret,
  LP("HYDRA-MSG/v1/init-chain/r2i") || LP(transcript_hash), 32)

refresh_root = HKDF-Expand(handshake_secret,
  LP("HYDRA-MSG/v1/refresh-root") || LP(transcript_hash), 32)
```

The initiator sends with `chain_i2r`; the responder sends with `chain_r2i`.
The opposite mapping is used for receive. There is no long-lived envelope MAC
key. Both direction counters start at zero. `handshake_secret`, `hybrid_prk`,
`confirm_key`, and `finish_key` are erased after FINISH processing. Only the
independently derived `refresh_root` and current direction chains remain.
Because `refresh_root` is a one-way sibling of the initial chain seeds, its
later compromise does not permit rederiving those initial seeds.

## 6. Signature policy and efficiency

The public envelope header has no signature field. Signatures are carried only
inside the bootstrap/control/application object that requires one.

Required ML-DSA signatures:

- one INIT signature and one RESP signature per session;
- one signature from each endpoint in an authenticated hybrid refresh;
- the required signature set on identity rotation (old and new keys) and
  device revocation records;
- the governance-required signature set on every group epoch commit; and
- one signature on every group data message in every group mode.

Ordinary 1:1 data, FINISH/REFRESH_FINISH, and close MUST NOT carry a
signature. Their peer authentication follows
from the signed handshake plus possession of the evolving AEAD keys.
This is channel authentication against outsiders, not transferable sender
proof: either session participant can construct a transcript that appears to
come from the other participant.

The protocol MUST NOT offer an “optional per-message signature” flag for 1:1
data. Applications needing transferable/non-repudiable evidence sign an
application object with a separate explicit content type; they do not change
the envelope authentication rules.

The envelope carries signature bytes only when the content requires a
signature. Ordinary 1:1 DATA therefore performs no public-key operation and
normally uses a Lite envelope. AEAD already authenticates ciphertext, class,
and outer header, so a second envelope HMAC and a ciphertext hash are forbidden
on the data path.

## 7. Message ratchet

For direction-specific chain key `CK_n` and index `n`:

```text
ratchet_context = session_id || u64(n)

MK_n = HKDF-Expand(
  CK_n,
  LP("HYDRA-MSG/v1/message-key") || LP(ratchet_context),
  32
)

CK_{n+1} = HKDF-Expand(
  CK_n,
  LP("HYDRA-MSG/v1/chain-advance") || LP(ratchet_context),
  32
)

AEAD_KEY_n = HKDF-Expand(
  MK_n,
  LP("HYDRA-MSG/v1/aead-key") || LP(ratchet_context),
  32
)

AEAD_NONCE_n = 12 zero bytes

ROUTE_TAG_n = HMAC-SHA3-256(
  MK_n,
  "HYDRA-MSG/v1/route-tag" || session_id || u64(n)
)[0..16]
```

`MK_n` and `AEAD_KEY_n` are one-use values. A fixed zero nonce is secure only
because each AEAD key seals at most one plaintext; immutable retransmission
reuses ciphertext and does not invoke AEAD again. The old chain key is erased
only as part of an atomic successful send, or after a successful receive
transaction commits. Receive processing MUST use provisional state so an
invalid ciphertext cannot advance the ratchet.

Each send chain has one exclusive mutation owner. Concurrent sends are
serialized or assigned distinct indices atomically before key derivation; no
two transactions may derive from the same chain state/index.

Compromise of `CK_n` reveals message `n` and future chain values until a
hybrid refresh. It does not reveal erased earlier chain/message keys under the
one-way-KDF assumption.

## 8. Replay and out-of-order delivery

The base profile is ordered. An implementation MAY enable bounded
out-of-order delivery with:

```text
MAX_SKIP = 256
REPLAY_WINDOW_WIDTH = MAX_SKIP + 1 = 257 positions
```

The replay window covers the current highest authenticated index plus the
previous 256 indices. Thus a forward gap of exactly 256 remains valid and its
oldest skipped key remains receivable once; a forward gap of 257 is rejected.

Before authentication, the receiver may provisionally derive at most
`MAX_SKIP + 1` candidates. It MUST NOT commit chain advancement, replay bits,
or skipped keys unless AEAD authentication and plaintext validation succeed.
Stored skipped message keys are one-use, non-serializable, bounded, and erased
on use or session close.

Messages beyond the bound are dropped or trigger a generic authenticated
resynchronization request. A resynchronization message MUST NOT transmit a
chain key or permit rollback.

## 9. Authenticated hybrid refresh

A refresh is a three-record mini-handshake carried by the authenticated
existing session. The endpoint starting it is the refresh initiator, regardless
of its original session role. INIT and RESP are also signed by the bound device
identity keys so compromise of chain state alone cannot forge a refresh.

The refresh initiator samples `refresh_id[32]`, generates fresh X25519 and
ML-KEM-768 keypairs, and sends under the old session:

```text
REFRESH_INIT_CORE =
  session_id ||
  handshake_transcript_hash[64] ||
  refresh_id ||
  initiator_identity_fingerprint ||
  responder_identity_fingerprint ||
  initiator_refresh_x25519_public ||
  initiator_refresh_mlkem_encapsulation_key ||
  u64(old_initiator_send_index) ||
  u64(old_initiator_receive_index)
```

```text
refresh_init_sig_digest = SHA3-512(
  "HYDRA-MSG/v1/refresh-init-signature" || suite_id ||
  LP(REFRESH_INIT_CORE)
)

refresh_init_signature =
  ML-DSA-65.Sign(refresh_initiator_identity_key, refresh_init_sig_digest)
```

REFRESH_INIT content is `REFRESH_INIT_CORE || refresh_init_signature`.

The refresh cutover barrier and exact interpretation of the four recorded
chain indices are normative in `state-machines.md`. Application sends pause
after REFRESH_INIT emission/acceptance; only refresh control records may be
newly emitted until install or abort.

The refresh responder rejects reused IDs, identity/state mismatch, invalid
public values, and an invalid signature before KEM work. It generates a fresh
X25519 keypair, encapsulates to the supplied ML-KEM key, computes:

```text
refresh_init_hash = SHA3-512(
  "HYDRA-MSG/v1/refresh" ||
  LP(REFRESH_INIT_CORE || refresh_init_signature)
)
```

It then forms:

```text
REFRESH_RESP_CORE =
  refresh_init_hash[64] ||
  responder_refresh_x25519_public ||
  refresh_mlkem_ciphertext ||
  u64(old_responder_send_index) ||
  u64(old_responder_receive_index)

refresh_pretranscript =
  SHA3-512(
    "HYDRA-MSG/v1/refresh" ||
    LP(REFRESH_INIT_CORE || refresh_init_signature) ||
    LP(REFRESH_RESP_CORE)
  )
```

Both reject an all-zero X25519 result and derive:

```text
refresh_prk = HKDF-Extract(
  salt = refresh_pretranscript,
  IKM  = LP(new_x25519_secret) || LP(new_mlkem_secret)
)

refresh_mix = HKDF-Expand(
  refresh_prk,
  LP("HYDRA-MSG/v1/refresh") || LP(session_id || refresh_pretranscript),
  32
)

candidate_handshake_secret =
  HKDF-Extract(salt = refresh_root, IKM = refresh_mix)

new_session_id = HKDF-Expand(
  candidate_handshake_secret,
  LP("HYDRA-MSG/v1/session-id") || LP(refresh_pretranscript),
  32
)

new_confirm_key = HKDF-Expand(
  candidate_handshake_secret,
  LP("HYDRA-MSG/v1/confirm-key") || LP(refresh_pretranscript),
  32
)
```

The responder computes:

```text
refresh_resp_confirm = HMAC-SHA3-256(
  new_confirm_key,
  "HYDRA-MSG/v1/resp-confirm" ||
  refresh_pretranscript || new_session_id
)

refresh_resp_sig_digest = SHA3-512(
  "HYDRA-MSG/v1/refresh-resp-signature" || suite_id ||
  refresh_pretranscript || new_session_id || refresh_resp_confirm ||
  LP(REFRESH_RESP_CORE)
)

refresh_resp_signature =
  ML-DSA-65.Sign(refresh_responder_identity_key, refresh_resp_sig_digest)

refresh_transcript = SHA3-512(
  "HYDRA-MSG/v1/refresh" ||
  LP(REFRESH_INIT_CORE || refresh_init_signature) ||
  LP(REFRESH_RESP_CORE || new_session_id ||
     refresh_resp_confirm || refresh_resp_signature)
)
```

REFRESH_RESP content is `REFRESH_RESP_CORE || new_session_id ||
refresh_resp_confirm || refresh_resp_signature` and remains encrypted under the
old session. The initiator verifies the signature and confirmation before
sending REFRESH_FINISH under:

```text
refresh_finish_key = HKDF-Expand(
  candidate_handshake_secret,
  LP("HYDRA-MSG/v1/finish-key") || LP(refresh_transcript),
  32
)
refresh_finish_nonce = 12 zero bytes
```

REFRESH_FINISH contains `refresh_transcript || new_session_id`. The zero nonce
is safe only because this independently derived key is one-use. New i2r/r2i
chains use `candidate_handshake_secret`, the initial-chain labels, and
`refresh_transcript` as context, and start at index zero. A new retained root
is derived as:

```text
new_refresh_root = HKDF-Expand(
  candidate_handshake_secret,
  LP("HYDRA-MSG/v1/refresh-root") || LP(refresh_transcript),
  32
)
```

The refresh initiator installs new state only after constructing
REFRESH_FINISH; the responder installs it only after successful REFRESH_FINISH
authentication.

INIT and RESP require the identity signatures above in addition to old-session
AEAD. Old refresh root, chains, skipped keys, replay windows, candidate
handshake secret, and all refresh temporaries are erased after the atomic state
swap. Failure preserves old persistent state and erases provisional state.

A successfully signed hybrid refresh restores future secrecy after a snapshot
compromise only if at least one fresh hybrid component remains unknown and the
attacker no longer controls the endpoint or identity signing key. An active
attacker can always block progress; a compromised identity key requires a new
externally authenticated identity/session rather than an in-session refresh.

If both endpoints initiate concurrently, the lexicographically lower
`refresh_id` wins. On receiving a lower ID, an endpoint aborts and erases its
own provisional refresh before responding; a higher ID receives a generic
authenticated busy response. An accepted `refresh_id` is retained in a
bounded recent-ID cache until the old session is erased.

## 10. Session close

CLOSE is an ordinary protected record under the next sending-chain key. Its
content is:

```text
u16(generic_reason_code)
```

The sender marks the session closing once the immutable CLOSE ciphertext is
emitted and sends no later application record. The receiver authenticates and
validates CLOSE before erasing session keys and reporting one generic closure.
An identical CLOSE ciphertext may be retransmitted; a new ciphertext at the
same index is forbidden. A dropped CLOSE is indistinguishable from transport
failure and provides no delivery guarantee.

## 11. Group profile

`group_mode` is authenticated group state. The three profiles are defined in
`group-modes.md`:

```text
Interactive  all authorized members send; TreeKEM; Standard/Full; attachments
Broadcast    presenters/moderators send; TreeKEM; Lite/Standard/Full
Lite         small text/reaction groups; direct wraps; Lite DATA only
```

Common roster, governance, commit, sender-chain, replay, mode-transition, and
identity-transition rules are in `group-rekey.md`. Interactive and Broadcast
membership updates use the post-quantum profile in `tree-kem.md`; Lite uses
bounded pairwise epoch wrapping.

Every group data object carries an ML-DSA-65 sender signature because members
with group traffic secrets can otherwise forge AEAD-valid sender fields.
Envelope class and group mode are included in the signature/KDF context.

## 12. Device revocation and identity rotation

Each physical/logical device is an independent endpoint and group member.
Revocation closes its sessions, removes its group memberships, advances every
affected group epoch, and distributes fresh epoch material only to remaining
devices. Revocation cannot retract plaintext or keys already received.

A revocation record is authorized by the application-level user/device roster
policy. Its canonical core and digest are:

```text
REVOCATION_CORE =
  user_id || device_id || revoker_fingerprint ||
  u64(roster_version) || u64(effective_epoch) || u16(reason_code)

revocation_digest = SHA3-512(
  "HYDRA-MSG/v1/device-revocation" || suite_id ||
  LP(REVOCATION_CORE)
)
```

Every policy-required authorized revoker signs the same digest. Roster version
must strictly increase, and the named device is rejected for new sessions as
soon as the authenticated revocation becomes effective.

The DEVICE_REVOCATION content is:

```text
LP(REVOCATION_CORE) ||
u8(signature_count, 1..16) ||
(revoker_fingerprint[32] || signature[3309]) * signature_count
```

Signature entries are strictly ordered and unique.

Identity rotation requires proof of possession of both keys:

```text
ROTATION_CORE =
  old_fingerprint || new_verification_key ||
  u64(rotation_index) || u64(valid_after_epoch) || nonce[32]

rotation_digest =
  SHA3-512(
    "HYDRA-MSG/v1/identity-rotation" || suite_id || LP(ROTATION_CORE)
  )
```

Both old and new keys sign `rotation_digest`. The rotation index strictly
increases. A verified identity is never silently replaced: application trust
policy must accept the handover. Every active 1:1 session involving the old
identity MUST close and establish a new signed handshake bound to the new
fingerprint; an in-session refresh cannot change identity binding. Every group
MUST accept the atomic identity-rotation commit defined in `group-rekey.md`
before accepting group data from the new key. Recovery without the old key is
outside HYDRA's cryptographic guarantees.

The IDENTITY_ROTATION content is:

```text
LP(ROTATION_CORE) || old_signature[3309] || new_signature[3309]
```

## 13. Failure handling

All untrusted input is parsed with fixed bounds. Unknown versions, suites,
modes, flags, content kinds, nonzero reserved fields, noncanonical encodings,
oversized lengths, invalid padding, invalid public keys, invalid signatures,
AEAD failures, replay failures, and state mismatches fail closed.

Receive processing order for protected records:

```text
1. Check exact record length and public fixed fields.
2. Select at most the bounded set of candidate session/group message keys.
3. Authenticate and decrypt AEAD into a temporary buffer.
4. Parse the entire fixed plaintext record and validate all reserved padding.
5. Verify duplicated index/session/group state and any required inner signature.
6. Apply replay checks to provisional state.
7. Atomically commit ratchet/replay/group state.
8. Deliver the application content.
```

No failure before step 7 mutates persistent cryptographic or delivery state.
Peer-visible failures collapse to no response, a generic authenticated close,
or a generic authenticated refresh-required response. Logs MUST NOT contain
secret keys, plaintext, raw decrypted padding, or distinguishable remote error
details.

Bootstrap processing is an unauthenticated CPU/memory DoS surface. Endpoints
MUST enforce per-source and global byte/operation limits, a fixed cap on
provisional handshakes, expiration, and backpressure before ML-DSA verification
or ML-KEM work. Protected-record candidate lookup is globally bounded; an
unknown route tag must not trigger an unbounded scan across sessions, groups,
senders, or skipped-key windows.

## 14. Security and privacy summary

| Property | v1 guarantee |
|---|---|
| 1:1 confidentiality | ChaCha20-Poly1305 under hybrid-established ratchet keys |
| Store-now-decrypt-later | ML-KEM-768 component, assuming it remains secure |
| Classical fallback | X25519 component, assuming the combiner and X25519 remain secure |
| Identity authentication | ML-DSA-65 plus an external fingerprint trust decision |
| Explicit key confirmation | RESP authenticator and FINISH |
| Past-message secrecy | After old keys and skipped keys are erased |
| Future secrecy after compromise | Conditional: signed refresh, fresh unknown component, trusted identity key, and no ongoing endpoint control |
| Replay protection | Per-direction bounded windows and one-use keys |
| 1:1 sender authentication | Live channel authentication against outsiders; not transferable proof |
| Group sender authentication | Required ML-DSA-65 signature on group data |
| Content length hiding | Exact length hidden within Lite/Standard/Full; class is public |
| Message type/identity/group metadata hiding after handshake | Encrypted inner header |
| Group workload modes | Authenticated Interactive, Broadcast, and encrypted Lite profiles |
| Bootstrap identity hiding | No |
| Public sequence leakage | A 64-bit counter is visible; route tags change per message |
| Timing, volume, endpoint, or transport-route hiding | No |
| Peer pseudonymity via one-time identities | App-layer pattern, not a protocol guarantee |
| Deniability, relay anonymity, or network anonymity | No |

Security depends on correct implementation, trustworthy endpoints, CSPRNG
quality, identity verification, bounded state handling, and prompt key erasure.
This document is not a substitute for independent cryptographic review.

## 15. Normative references

- [NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final).
- [NIST FIPS 204, Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final).
- [NIST SP 800-227, Recommendations for Key-Encapsulation Mechanisms](https://csrc.nist.gov/pubs/sp/800/227/final).
- [RFC 7748, Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748).
- [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/rfc/rfc5869).
- [RFC 8439, ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439).
