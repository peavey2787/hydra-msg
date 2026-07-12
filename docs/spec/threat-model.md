# HYDRA-MSG v1 formal threat model

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
- [Canonical encrypted local snapshot persistence](canonical-snapshot-persistence.md)

Status: normative v1 threat model.

This document defines the security claim boundary for HYDRA-MSG v1. A claim in
another HYDRA-MSG document is valid only under the assumptions and exclusions
listed here. When a lower-level implementation detail and this threat model
conflict, this document defines the intended security boundary and the
implementation must be corrected or the claim must be narrowed.

## 1. System boundary

HYDRA-MSG v1 provides an app-facing encrypted messaging SDK facade over internal
identity, contact, session, packet-fragment, lobby/group, backup, and encrypted
local-state components.

The public SDK boundary is intentionally small:

- open or create encrypted local state;
- create, import, unlock, lock, rotate, rename, and delete device identities;
- create and verify contact cards/invites;
- establish, refresh, close, and inspect sessions;
- configure one app-visible packet ceiling with `set_packet_size(bytes)`;
- send messages as one or more opaque HYDRA packets;
- receive one opaque HYDRA packet at a time and return a completed message only
  after internal reassembly succeeds;
- create, join, update, send to, and close lobbies/groups;
- export, import, and verify encrypted backups; and
- report diagnostics and benchmark results.

The app, not HYDRA-MSG, owns the carrier: WebRTC, files, HTTP, relays, libp2p,
mailboxes, QR codes, Kaspa pointers, or any other transport. HYDRA-MSG treats
carrier input/output as opaque bytes. HYDRA-MSG does not provide network
availability, NAT traversal, relay anonymity, account identity, push
notifications, spam protection, or carrier trust.

## 2. Protected assets

HYDRA-MSG aims to protect these assets against the in-scope adversaries:

- 1:1 message plaintext and attachments;
- lobby/group message plaintext and attachments;
- protected inner metadata, including message kind and fragment records;
- live and previously used handshake, refresh, chain, message, AEAD, and group
  secrets after honest erasure;
- device identity signing keys and encrypted identity vault records;
- peer authentication and safety-code state;
- session replay, counter, skipped-key, refresh, and close state;
- group roster, role, policy, epoch, commit-chain, sender-chain, and rekey
  integrity;
- encrypted backup payloads and encrypted local snapshot payloads; and
- rollback evidence needed to reject stale local state where implemented.

The following are not confidential assets in v1:

- public identity verification keys, contact cards, invite public material, and
  bootstrap public keys;
- outer envelope mode, outer counter, route tag, packet count, and padded packet
  class;
- app-selected packet-size ceiling;
- timing, direction, frequency, and carrier endpoint metadata;
- carrier account, relay, IP, browser-origin, mailbox, and delivery metadata;
- group membership information known to authorized group members; and
- plaintext or keys intentionally exposed by endpoints or authorized peers.

## 3. Security goals

Under the trust assumptions in Section 7, HYDRA-MSG v1 aims to provide:

1. Confidentiality and integrity for protected 1:1 and group records against
   outsiders.
2. Mutual device authentication after the application accepts the relevant
   device identity fingerprints through an explicit trust decision or verified
   roster.
3. Hybrid 1:1 key establishment where confidentiality remains secure if at
   least one of X25519 or ML-KEM-768 remains secure and the combiner assumptions
   hold.
4. Store-now-decrypt-later resistance from the ML-KEM-768 component, assuming
   ML-KEM-768 and the surrounding implementation remain secure.
5. ML-DSA-65-authenticated identity, handshake, refresh, and group-origin
   claims within their documented domains.
6. Explicit transcript binding and key confirmation for handshake and refresh
   flows.
7. Forward secrecy for erased past message keys and erased past chain states.
8. Bounded post-compromise recovery after a successful identity-signed hybrid
   refresh, fresh uncompromised entropy, and honest erasure after attacker
   access ends.
9. Replay rejection, counter monotonicity, and failure-atomic state advancement
   for authenticated records.
10. Group mode, role, membership, epoch, and rekey integrity according to the
    group specs.
11. Exact content-length hiding within the selected fixed HYDRA packet class:
    Lite, Standard, or Full.
12. Internal fragmentation and reassembly that never exposes fragment ids, part
    counts, or fragment records to app developers.
13. Encrypted local state and backup payload authentication under the supplied
    state or backup password.
14. No plaintext, private-key, session, group-chain, or backup-payload fallback
    to localStorage, logs, diagnostics, or durable-looking in-memory state.

## 4. Explicit non-goals

HYDRA-MSG v1 does not claim:

- endpoint compromise resistance while plaintext or keys are live;
- automatic or instantaneous post-compromise healing without an authenticated peer round trip, fresh uncompromised entropy, and attacker loss of endpoint access;
- operating-system, kernel, hypervisor, firmware, DMA, or hardware compromise
  resistance;
- network anonymity, IP hiding, relay anonymity, traffic-flow confidentiality,
  or global passive-adversary unlinkability;
- deniability for group messages with required ML-DSA sender signatures;
- non-repudiation or trusted timestamps;
- availability, delivery, mailbox reliability, spam resistance, or censorship
  resistance;
- protection against authorized recipients leaking plaintext or keys;
- protection against malicious app code wrapping the SDK;
- browser storage permanence after user site-data deletion, private browsing,
  eviction, profile reset, or origin migration;
- security if the chosen cryptographic parameter sets are cryptanalytically
  broken;
- security against malicious compilers, dependencies, build systems, RNGs, or
  update channels; or
- production-final status without the release gates listed in Section 14.

Anonymous-feeling chats are an application provisioning pattern, not a magic
property of a reusable identity. Unlinkability requires fresh one-time
identities/invites plus no account, contact-card, carrier, mailbox, browser
origin, relay, timing, or payment reuse that links sessions.

## 5. Adversary model

### 5.1 Passive network adversary

The adversary can observe, record, correlate, and indefinitely store all HYDRA
packets and all carrier metadata. The adversary learns timing, direction,
packet count, padded packet class, outer mode, outer counter, route tags,
transport endpoints, relays, mailbox identifiers, browser origins, and any
carrier metadata outside HYDRA.

The adversary must not learn protected plaintext or protected inner metadata
without breaking an assumption in Section 7.

### 5.2 Active network adversary

The adversary can inject, modify, replay, reorder, duplicate, truncate, delay,
and drop any carrier packet. The adversary can submit arbitrary malformed
contact cards, invites, envelopes, backups, snapshots, packets, and group
records. The adversary can open many connections or accounts and can force the
application to process attacker-controlled bytes.

The adversary must not authenticate as another accepted device, alter an
authenticated record, advance ratchet/epoch/replay state on failed validation,
force nonce/key reuse, or complete reassembly of an unauthenticated fragment.
The adversary can always deny service and can cause bounded resource use.

### 5.3 Quantum recording adversary

The adversary records current traffic and later obtains a cryptographically
relevant quantum computer. Past confidentiality then depends on ML-KEM-768,
SHA3/HMAC/HKDF, ChaCha20-Poly1305, implementation correctness, and erasure. It
does not depend solely on X25519.

Authentication depends on ML-DSA-65 and the accepted identity-binding process.
HYDRA-MSG v1 does not promise security if the pinned ML-KEM or ML-DSA parameter
sets are broken.

### 5.4 Malicious authenticated peer

A legitimate 1:1 peer can deviate from the protocol, retain secrets that honest
implementations erase, submit malformed application data, leak plaintext or
keys, and falsely describe received content.

A 1:1 recipient can fabricate plausible symmetric-channel transcripts because
both sides know the relevant receiving-direction keys. Ordinary 1:1 messages
are channel-authenticated against outsiders but are not transferable proof of
authorship.

### 5.5 Malicious group member

An authorized group member can read group plaintext for epochs in which that
member is authorized. The member can leak plaintext, retain group secrets, try
to fork commits, submit malformed records, withhold messages, or create valid
messages under its own signing key.

HYDRA-MSG aims to prevent one group member from forging another uncompromised
member's required ML-DSA group-origin signature. A valid group signature proves
possession of the signing key for the message domain, not a trusted timestamp
or honest endpoint behavior.

### 5.6 State-snapshot adversary

At time `t`, the adversary obtains selected live process memory, storage files,
browser database records, VM snapshots, or backups, then loses access. The
consequences depend on which secrets were obtained, as summarized in Section
8. A temporary snapshot is not the same as permanent endpoint control.

### 5.7 Rollback adversary

The adversary can restore stale encrypted local-state files, stale IndexedDB
records, stale backups, stale VM snapshots, or stale filesystem snapshots.
Reusing ratchet or group-chain state can repeat one-use keys or reverse
security progress, so rollback protection and generation floors are required
for durable local state. A backup restore must not lower the target rollback
floor.

### 5.8 Local privileged adversary

An adversary controlling the process, kernel, hypervisor, debugger,
DMA-capable device, firmware, hardware, browser engine, or JavaScript context
while secrets are live is outside the confidentiality guarantee. Memory
zeroization reduces exposure after honest use but does not defeat this
adversary.

### 5.9 Supply-chain adversary

A malicious or defective compiler, dependency, cryptographic backend, RNG,
wasm-bindgen toolchain, release process, or update channel can invalidate every
claim. HYDRA-MSG mitigates but does not cryptographically solve this risk with
pinned algorithms, vectors, QA gates, dependency review, reproducible-release
goals, and external review.

## 6. Carrier and packet-size boundary

`set_packet_size(bytes)` is a carrier-facing ceiling. HYDRA-MSG selects the
largest fixed HYDRA packet class that fits below that ceiling. If a protected
payload does not fit in one selected class, HYDRA-MSG internally fragments the
protected payload and `send()` returns multiple opaque packets. The app must
send every returned packet and feed each incoming packet to `receive()` or
`receive_lobby()` one at a time.

HYDRA-MSG guarantees only that each returned HYDRA packet is at or below the
configured packet ceiling. It does not guarantee that the underlying carrier
will preserve packet boundaries. A carrier may fragment, coalesce, reorder,
delay, duplicate, or drop packets. The app or carrier layer must provide any
required framing, ordering, retry, congestion control, delivery receipts, or
backpressure.

The packet-fragment layer is internal. App developers must not see fragment
ids, part counts, fragment records, padding classes, replay windows, chain
keys, or session exports. If future public API changes expose those concepts,
the threat model and public API spec must be updated first.

## 7. Trust assumptions

Security requires all of the following:

- device fingerprints are authenticated by an out-of-band channel, verified
  roster, or explicit visible trust-on-first-use decision;
- applications correctly enforce trust, revocation, rotation, group policy,
  and block/remove decisions;
- at least one hybrid confidentiality component remains secure;
- ML-DSA-65 remains unforgeable for the relevant identity, refresh, and group
  domains;
- SHA3-256, SHA3-512, HMAC-SHA3-256, HKDF, and ChaCha20-Poly1305 satisfy their
  required properties;
- the OS or browser CSPRNG provides unpredictable independent entropy;
- cryptographic implementations are correct, side-channel resistant where
  required, and apply official errata without silent wire incompatibility;
- domain-separation labels and transcript bindings are unique and reviewed;
- old secrets are erased according to `../impl/memory-zeroization.md`;
- send-state and transaction rules prevent sealing two plaintexts with the
  same one-use AEAD key and nonce;
- every parser and state machine applies bounded memory and bounded-work rules
  before attacker-controlled expensive work when possible;
- durable persistence uses authenticated encrypted snapshots and rollback
  evidence as specified; and
- the application does not leak plaintext or keys outside HYDRA-MSG.

Wall-clock synchronization is not a security assumption. Protocol freshness
comes from nonces, transcript binding, counters, replay windows, and commit
ancestry, not trusted timestamps.

## 8. Compromise consequences

| Compromised material | Immediate consequence | Not revealed under assumptions | Recovery |
|---|---|---|---|
| Identity verification key | No secret consequence | Secret signing keys and session/group secrets | None required |
| Identity signing key | Device impersonation, forged handshakes, forged refreshes, forged rotations, future identity signatures | Previously encrypted plaintext without session/group state | Revoke externally, replace identity, establish new sessions/groups |
| Provisional handshake secret before erasure | Candidate session and both initial chains | Other independent sessions | Abort/close and perform a new handshake |
| Current send chain key | Current and future messages in that direction | Erased earlier messages and opposite direction | Identity-signed hybrid refresh after attacker access ends |
| Current receive chain key | Current and future peer messages in that direction; local transcript forgery | Erased earlier messages and opposite direction | Identity-signed hybrid refresh after attacker access ends |
| One message/AEAD key | That one message | Other message keys and chain keys | Erase key; refresh only if compromise scope is unclear |
| Skipped-key store | Exactly the retained skipped messages | Erased and non-skipped messages | Erase store; refresh if compromise scope is unclear |
| Refresh root alone | May contribute to a later refresh if fresh secrets are also obtained | Current/past plaintext and sibling chain seeds | Replace at next successful hybrid refresh |
| Refresh root plus current chains | Current/future traffic until recovery | Erased earlier messages | Identity-signed hybrid refresh with fresh entropy |
| Group sender/receiver chain for one epoch | Current/future traffic for that chain; insider AEAD-valid records | Other members' ML-DSA signing keys and erased prior chains | Remove compromised device and install fresh epoch |
| Group epoch secret before setup erasure | All sender-chain seeds for that epoch | Prior epochs | Abort install or immediately create fresh epoch |
| TreeKEM private path | Candidate/subsequent roots decryptable through that path | Erased prior roots and other members' identity keys | Clean identity-signed self-update after endpoint recovery |
| Encrypted local state file only | Offline password-guessing target; rollback attempt if stale | Plaintext if password/KDF remains strong | Reject stale generation; rotate password if exposed |
| Encrypted backup only | Offline password-guessing target | Plaintext if password/KDF remains strong | Rotate backup password and create new backup if exposed |
| Backup password plus backup | Restored local identity/contact/message/lobby state in that backup | Live sessions not present in backup | Revoke/rotate as needed; restore must preserve target generation floor |
| Full endpoint while live | All plaintext and live keys accessible to that endpoint; active impersonation | Secrets held only by uncompromised endpoints | No in-protocol guarantee; remediate endpoint and re-establish trust |

Compromise claims require honest erasure. A malicious endpoint may retain any
secret it legitimately receives.

## 9. Persistence and backup boundary

Native and browser persistence store opaque authenticated encrypted snapshots.
The storage adapter must not parse plaintext secrets. Browser IndexedDB
persistence is encrypted but not guaranteed permanent: private browsing,
site-data deletion, quota eviction, browser profile reset, and mobile lifecycle
policies can remove state. Exported encrypted backups remain required for
portability and disaster recovery.

`verify_backup(bytes, password)` must authenticate/decrypt and validate the
backup payload without mutating state. `import_backup(bytes, password)` must
validate before mutation and must revert in-memory state if durable persistence
fails. A valid old backup must not lower the local rollback-generation floor.

HYDRA-MSG must never fall back to plaintext storage, localStorage, unencrypted
IndexedDB records, logs, or durable-looking in-memory state when persistence
fails. Quota and filesystem errors must be surfaced to the application.

## 10. Authentication boundaries

Handshake signatures authenticate device keys only after the application
accepts the corresponding fingerprint. A mathematically valid signature from
an untrusted key proves no human, account, or legal identity.

Contact cards and lobby invites are bearer artifacts. Anyone who receives a
valid invite may attempt to use it until policy, one-time semantics, expiration,
or application governance rejects it. Applications must not treat receipt of an
invite as proof of a human identity.

Identity rotation requires the documented old/new key authorization and an
application trust decision. Rotation creates a new identity binding; existing
sessions close and perform a new handshake. Rotation and revocation do not
retract already delivered plaintext.

## 11. Metadata and privacy boundaries

HYDRA-MSG hides exact protected content length within the selected packet
class, protected content kind, fragment records, contact/session identifiers
inside protected payloads, group mode/epoch where protected, and inner flags
after establishment.

HYDRA-MSG does not hide:

- whether a record is bootstrap or protected;
- padded packet class and packet count;
- outer counter and route tag;
- packet timing, direction, loss, retransmission, and carrier ordering;
- transport endpoints, relays, accounts, browser origins, and mailbox routing;
- group fanout and approximate group size from delivery patterns;
- membership information known to authorized members; or
- plaintext disclosed by endpoints.

Changing route tags prevent a stable protocol-level session identifier, but
traffic patterns and carrier metadata may still link records. Fixed-class
padding is not traffic-flow confidentiality. Carriers must not apply
content-dependent compression to protected HYDRA bytes if packet-size privacy
is desired.

## 12. Denial of service and resource bounds

Availability is not a v1 security guarantee. Implementations must bound:

- bytes per parser input and decoded record;
- pending handshakes, refreshes, contacts, lobbies, sessions, and messages;
- pending packet fragments per peer/lobby and fragment lifetime;
- skipped keys, replay windows, route-tag candidates, group senders, and group
  members;
- backup, state, contact-list, message-export, and attachment import sizes;
- ML-KEM, ML-DSA, AEAD, hash, and KDF operations per interval; and
- filesystem, IndexedDB, and memory allocation during attacker-controlled
  operations.

Resource rejection should happen before expensive cryptography when safe and
must not create secret-dependent peer-visible distinctions. Puzzles, payments,
account reputation, proof of work, and network-level anti-abuse are outside
HYDRA-MSG v1.

The concrete implementation ceilings and enforcement points are recorded in
[`resource-exhaustion-dos-limits.md`](../../docs/validation/evidence/resource-exhaustion-dos-limits.md).
The explicit persistence crash/failure regression matrix is recorded in
[`crash-consistency-matrix.md`](../../docs/validation/evidence/crash-consistency-matrix.md).
The WASM/browser lifecycle and multi-tab concurrency policy is recorded in
[`wasm-browser-lifecycle-policy.md`](../../docs/validation/evidence/wasm-browser-lifecycle-policy.md).
The application must still rate-limit carrier ingress before buffering complete
objects and must bound concurrent calls, queues, connections, and durable storage.

## 13. Failure, oracle, and side-channel requirements

Authentication, signature, replay, epoch, trust, parsing, KDF, and decryption
failures must not leak secret material. Persistent state changes only after all
required checks succeed. Failed partial receives may update only bounded
non-secret parser/reassembly bookkeeping required for safe operation.

Constant-time requirements apply to secret-dependent cryptographic operations
and authentication comparisons. Public length, version, and syntax rejection do
not need to be constant-time. Error timing, logs, allocation patterns, panic
messages, debug formatting, browser console output, and backend diagnostics
must not intentionally reveal secret material.

Chosen-ciphertext behavior is handled by AEAD authentication, ML-KEM
construction requirements, and key confirmation. ML-KEM implicit-rejection
details and backend errors are not exposed to peers.

## 14. Release-status boundary

This threat model is a security specification, not proof that the current code
is production-final. HYDRA-MSG must not be called production-ready or
enterprise-grade until the release criteria require at least:

- final positive and negative frozen vectors for persistence, envelopes,
  handshakes, sessions, packet fragments, groups, and backups;
- adversarial parser/state-machine tests and long-running fuzz coverage;
- active cargo-audit/cargo-deny/license/advisory gates with clean release evidence;
- Miri, sanitizer where applicable, and fault-injection gates;
- SBOM, reproducible release package, signed tags/artifacts, and documented
  release process;
- transcript/domain-separation review;
- session/replay/key-evolution review;
- group rekey and TreeKEM review;
- browser persistence lifecycle and multi-tab concurrency review; and
- external cryptography/protocol review.

`security-proof-sketch.md` maps claims to assumptions. It is not an external
security proof. `../validation/release-criteria.md` and
`../validation/release-criteria.md` and `../validation/release-checklist.md` define the current release gate status.

## Metadata-leakage boundary

The metadata boundary is maintained in `docs/validation/evidence/metadata-leakage-audit.md`. HYDRA minimizes avoidable SDK-level metadata leakage, but it must not claim metadata-free transport, anonymous by default routing, traffic-flow privacy, or fully unlinkable bearer anonymous auth. Packet count, timing, endpoints, relay/mailbox access patterns, backup/state chunk count, browser/OS storage metadata, and issuer/carrier correlation remain visible unless the carrier adds stronger privacy machinery.
