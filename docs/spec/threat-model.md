# HYDRA-MSG v1 threat model and security claim boundaries

This document is normative. It defines the adversaries, trusted components,
security goals, compromise consequences, and exclusions for HYDRA-MSG v1. A
claim in another HYDRA document is valid only under the assumptions stated
here.

## 1. Protected assets

HYDRA protects:

- 1:1 and group application plaintext;
- live and previously used handshake, refresh, chain, message, AEAD, and group secrets;
- device identity signing keys;
- peer and group sender authentication state;
- group roster, governance, epoch, and commit-chain integrity;
- replay and ordering state; and
- encrypted content length and protected inner metadata.

Public keys, signatures, bootstrap records, outer modes, envelope class, route
tags, public counters, record count, timing, size, network endpoints, and
transport routing information are not confidential assets.

## 2. Security goals

Under the assumptions in Section 4, v1 aims to provide:

1. Confidentiality and integrity of protected records against outsiders.
2. Mutual device authentication for 1:1 establishment after an external trust
   decision binds each ML-DSA-65 fingerprint to the intended device.
3. Hybrid 1:1 key establishment such that confidentiality remains secure if at
   least one of X25519 or ML-KEM-768 remains secure and the combiner assumptions
   hold.
4. Store-now-decrypt-later resistance from the ML-KEM-768 component.
5. Explicit handshake and refresh key confirmation.
6. Past-message secrecy after old chain/message/skipped keys and the
   chain-generating handshake secret are erased.
7. Conditional recovery from a chain-state snapshot after an identity-signed
   hybrid refresh with fresh uncompromised entropy.
8. Replay rejection and atomic failure behavior.
9. Group mode/role/membership integrity, epoch separation, join secrecy,
   removal security, and ML-DSA-authenticated sender attribution.
10. Exact content-length hiding within each Lite, Standard, or Full class.

The protocol does not claim information-theoretic security, everlasting
authentication, anonymity, availability, endpoint security, or guaranteed
physical memory erasure.

## 3. Adversary classes

### 3.1 Passive network adversary

The adversary can observe, record, correlate, and indefinitely retain all
traffic and public bootstrap material. The adversary learns traffic timing,
direction, count, envelope class/size, public outer mode, public counter,
transport endpoints, and any routing metadata outside HYDRA.

The adversary must not learn protected plaintext or encrypted inner metadata,
subject to primitive security and endpoint assumptions.

### 3.2 Active network adversary

The adversary can inject, modify, replay, reorder, delay, duplicate, truncate,
and drop records; open many connections; and present arbitrary public keys and
malformed encodings.

The adversary must not establish an authenticated session without an accepted
identity key, alter an authenticated record, force ratchet/epoch/replay state
advancement on failure, or create nonce reuse. The adversary can always deny
service and can cause bounded resource consumption.

### 3.3 Quantum recording adversary

The adversary records current traffic and may later obtain a cryptographically
relevant quantum computer. Past confidentiality then depends on ML-KEM-768,
SHA3/HMAC/HKDF, ChaCha20-Poly1305, implementation correctness, and key erasure;
it does not depend solely on X25519.

Authentication relies on ML-DSA-65. The protocol does not promise security if
the pinned ML-KEM or ML-DSA parameter set is cryptanalytically broken.

### 3.4 State-snapshot adversary

At time `t`, the adversary obtains selected live process state, then loses
access. Consequences depend on the exact secret obtained and are specified in
Section 5. A snapshot is not equivalent to permanent endpoint control.

### 3.5 Malicious authenticated peer or group member

A legitimate peer or active group member may deviate arbitrarily, retain
secrets that honest implementations erase, submit malformed content, fork
group commits, leak plaintext/keys, or falsely describe application data.

HYDRA cannot keep group plaintext secret from an authorized group member. A
1:1 recipient can fabricate symmetric-channel transcripts, so ordinary 1:1
data is not transferable proof of authorship. Required group ML-DSA signatures
prevent one member from attributing a newly forged group message to another
uncompromised signing key, but they do not provide a trusted timestamp.

Group epoch entropy is committer-generated, not contributory. In Lite mode,
the signed epoch-secret commitment detects inconsistent direct-wrap secrets.
In Interactive and Broadcast modes, the authenticated update path, tree hash,
and root confirmation detect inconsistent TreeKEM roots. These checks cannot
prove entropy quality or prevent an authorized committer from leaking the
root. That limitation is inherent because the committer is an authorized
recipient of group plaintext.

Interactive and Broadcast TreeKEM reduce balanced-tree membership update work
but do not make authorized members trustworthy. Broadcast audience records
cannot pass the presenter-role signature check even if a malicious audience
member constructs AEAD-valid ciphertext. Lite mode remains encrypted and
retains required group sender signatures.

### 3.6 Local privileged adversary

An adversary controlling the process, kernel, hypervisor, debugger, DMA-capable
device, firmware, or hardware while secrets are live is outside the
confidentiality guarantee. Memory hardening reduces exposure but does not
defeat this adversary.

### 3.7 Rollback and persistence adversary

The adversary can restore stale files, snapshots, virtual machines, or
application databases. Reusing persisted ratchet state can repeat an AEAD key
and fixed nonce, which is catastrophic.

HYDRA therefore defines no live session, group-chain, or TreeKEM-private-path
persistence. Restart closes sessions and requires a new handshake; group
traffic requires a fresh epoch/tree welcome. Any persistence extension
requires monotonic rollback protection and independent review.

### 3.8 Supply-chain and backend adversary

A malicious or defective compiler, cryptographic backend, dependency, RNG,
build system, or update channel can invalidate every guarantee. v1 mitigates
but does not cryptographically solve this risk through pinned algorithms,
known-answer tests, dependency review, reproducible-build goals, and release
gates.

## 4. Trust assumptions

Security requires all of the following:

- device fingerprints are authenticated through an out-of-band, verified
  roster, or explicitly visible trust-on-first-use decision;
- endpoint applications enforce trust, revocation, rotation, and group
  governance policy correctly;
- at least one hybrid confidentiality component remains secure;
- ML-DSA-65 remains unforgeable for identity and group-origin claims;
- SHA3-256/SHA3-512, HMAC-SHA3-256, HKDF, and ChaCha20-Poly1305 satisfy their
  required properties;
- the OS CSPRNG provides unpredictable, independent entropy;
- cryptographic implementations are correct, constant-time where required,
  and apply official errata without silent wire incompatibility;
- old secrets are erased according to `memory-zeroization.md`;
- transaction and send-state rules prevent sealing two plaintexts with the
  same one-use AEAD key;
- local resource bounds are enforced before attacker-controlled expensive
  work; and
- the application does not disclose plaintext outside HYDRA.

Wall-clock synchronization is not a security assumption. Nonces, transcript
binding, monotonic protocol counters, replay windows, and commit ancestry—not
timestamps—provide protocol freshness.

## 5. Compromise matrix

| Compromised material | Immediate consequence | Not revealed under assumptions | Recovery |
|---|---|---|---|
| Identity verification key | No secret consequence | All secret keys | None required |
| Identity signing key | Device impersonation, forged handshakes/refreshes/rotations and future signatures | Previously encrypted plaintext without session/group state | Revoke through external policy, replace identity, establish new sessions/groups |
| Provisional handshake secret before erasure | Entire candidate session, both initial chains and confirmation keys | Other independent sessions | Abort/close; establish a new handshake |
| Current send chain key | Current and future messages in that direction | Erased earlier messages and opposite chain | Identity-signed hybrid refresh after attacker loses access |
| Current receive chain key | Current and future peer messages in that direction; local transcript forgery | Erased earlier messages and opposite chain | Identity-signed hybrid refresh after attacker loses access |
| One message/AEAD key | That one message | Other message and chain keys | Erase key; no session-wide action if exposure is isolated |
| Skipped-message store | Exactly the retained skipped messages | Erased and non-skipped messages | Erase store; refresh if compromise scope is uncertain |
| Refresh root alone | Ability to participate in combining a later refresh if fresh secrets are also obtained | Current/past message plaintext and sibling chain seeds | Replace at the next successful hybrid refresh |
| Refresh root plus current chains | Current/future traffic until recovery | Erased earlier messages | Identity-signed hybrid refresh, assuming fresh entropy and no ongoing control |
| Group sender/receiver chains for one epoch | Current/future traffic for those chains; AEAD-valid insider forgeries | Other members' ML-DSA signing keys; erased earlier chain states | Remove compromised device and install a fresh epoch |
| Group epoch secret before setup erasure | All sender-chain seeds for that epoch | Prior epochs | Abort installation or immediately create a fresh epoch |
| TreeKEM private path | Candidate/subsequent roots decryptable through that path | Erased prior roots and other members' identity keys | Clean identity-signed self-update after endpoint recovery |
| Full endpoint while live | All plaintext and keys accessible to that endpoint; active impersonation | Secrets held only by uncompromised endpoints | No in-protocol guarantee; remediate endpoint and re-establish trust |

Compromise claims assume honest erasure. A malicious endpoint may retain any
secret it has legitimately received.

## 6. Forward secrecy and post-compromise security

The symmetric chain is one-way:

- compromise of `chain_key[n]` does not reveal erased earlier chain/message
  keys; and
- compromise of `chain_key[n]` does reveal the current and all computable
  future states until refresh.

The chain-generating handshake secret is erased after FINISH. The retained
refresh root is a domain-separated sibling and cannot derive the initial
chains under the HKDF assumption. Retaining the original handshake secret
would defeat past-message secrecy and is forbidden.

HYDRA does not claim unconditional post-compromise security. Recovery requires:

1. the attacker no longer controls the endpoint;
2. the identity signing key used for refresh remains trustworthy;
3. at least one fresh X25519/ML-KEM contribution is unknown to the attacker;
4. the signed refresh completes with key confirmation; and
5. old roots, chains, skipped keys, and provisional material are erased.

An active attacker can block refresh. A compromised identity key cannot be
repaired by an in-session refresh.

## 7. Authentication boundaries

Handshake signatures authenticate device keys only after the application
accepts the corresponding fingerprints. A mathematically valid signature from
an untrusted key proves no human or account identity.

Ordinary 1:1 AEAD records provide live channel authentication against outsiders
but not non-repudiation or transferable sender evidence. Either participant
holds the receiving-direction chain needed to construct a plausible transcript.

Group AEAD keys are known to active group members. Therefore group sender
attribution requires the inner ML-DSA signature. A valid signature proves key
possession at verification time, not when the alleged event occurred.

Identity rotation requires both old- and new-key signatures plus application
acceptance. It creates a new identity binding: existing sessions close and
perform a new handshake. Revocation and rotation do not retract already
delivered plaintext.

## 8. Metadata and privacy

HYDRA hides exact protected content length, content kind, session/group ID,
sender ID, group mode, epoch, state version, and inner flags after
establishment.

HYDRA does not hide:

- bootstrap identity verification keys and handshake public material;
- whether a record is bootstrap or protected;
- envelope class: Lite (4 KiB), Standard (32 KiB), or Full (144 KiB);
- the 64-bit outer counter;
- record timing, count, direction, and class size;
- network endpoints or transport routing data;
- membership-change fanout, which may reveal approximate group size;
- group membership from members themselves; or
- plaintext disclosed by endpoints.

Changing route tags prevent a stable protocol-level session identifier, but
transport context and traffic patterns may still link records. Each class
hides exact length only within that class; class selection leaks a coarse size
bucket. Fixed-class padding is not traffic-flow confidentiality. Class size
exists at the HYDRA record layer; lower layers may fragment/coalesce it. A
transport MUST NOT apply content-dependent compression if the class privacy
claim is to be preserved.

## 9. Denial of service

Availability is not guaranteed. Implementations must bound:

- bytes and partial records per source;
- provisional handshakes and refreshes;
- ML-DSA verification and ML-KEM operations per interval;
- live sessions, groups, senders, route-tag candidates, replay windows, and
  skipped keys;
- envelope-class buffers, TreeKEM paths/fragments, group members, signatures,
  policies, and welcomes; and
- queued immutable retransmissions and scratch cleanup buffers.

Resource rejection occurs before expensive cryptography when safe and exposes
no secret-dependent peer-visible distinction. Puzzles, payments, account
reputation, and network-level anti-abuse are outside v1.

## 10. Failure, oracle, and side-channel requirements

Remote-visible authentication, signature, replay, epoch, trust, and parsing
failures collapse to generic behavior. Persistent state changes only after all
required checks succeed.

Constant-time requirements apply to secret-dependent cryptographic operations
and authentication comparisons. Public length/version rejection need not be
constant-time. Error timing, logs, allocation patterns, cache behavior, and
backend diagnostics must not intentionally reveal secret material.

Chosen-ciphertext behavior is handled by the AEAD and ML-KEM constructions plus
key confirmation. ML-KEM implicit-rejection details and backend errors are not
exposed to peers.

## 11. Residual risks and release status

Even a conforming implementation remains exposed to:

- undiscovered cryptanalysis;
- implementation and side-channel defects;
- identity-verification mistakes;
- malicious authorized endpoints;
- traffic analysis;
- denial of service;
- operating-system and hardware compromise; and
- supply-chain failure.

The documentation is a design specification, not evidence of a security proof.
Production claims require the complete vectors in `test-vectors.md`, two
independent interoperable implementations, fuzzing, implementation review, and
independent cryptographic review.

`security-proof-sketch.md` maps claims to assumptions without elevating them
to a proof. `release-criteria.md` is authoritative for freeze status.
