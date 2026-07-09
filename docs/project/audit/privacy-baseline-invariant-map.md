# Privacy baseline and invariant map

Status: P1 facade handshake confidentiality verification complete.

This audit defines the current privacy claims, their implementation owners, and the unsupported properties that must stay marked as future work until later privacy-hardening phases implement them. It is maintainer/assistant working evidence, not public release documentation.

## Scope

Audited public documentation:

```text
README.md
docs/spec/README.md
docs/spec/protocol-spec.md
docs/spec/public-developer-api.md
docs/spec/threat-model.md
docs/impl/message-flow/README.md
docs/impl/carrier-examples.md
docs/impl/wasm-javascript-bindings.md
docs/validation/production-qa-gate.md
docs/validation/release-criteria.md
docs/validation/release-readiness.md
```

Audited facade implementation areas:

```text
crates/hydra-msg/src/identity.rs
crates/hydra-msg/src/contacts.rs
crates/hydra-msg/src/handshake.rs
crates/hydra-msg/src/messages.rs
crates/hydra-msg/src/lobbies.rs
crates/hydra-msg/src/storage.rs
crates/hydra-msg/src/codec/identity.rs
crates/hydra-msg/src/codec/contacts.rs
crates/hydra-msg/src/codec/handshake.rs
crates/hydra-msg/src/codec/lobbies.rs
crates/hydra-msg/src/codec/messages.rs
crates/hydra-msg/src/codec/storage.rs
crates/hydra-msg/src/tests.rs
crates/hydra-msg/src/handshake_tests.rs
qa/ci/check-privacy-invariants.sh
qa/ci/check-privacy-invariants.ps1
```

## Privacy-claim inventory

| Claim area | Current public wording | Implementation owner | P0 status |
|---|---|---|---|
| Normal messages are encrypted | README and public API describe encrypted HYDRA envelopes carried by app transports. | `handshake.rs`, `messages.rs`, `codec/handshake.rs`, `hydra-session` use through `SessionState`. | Supported for facade send/receive after authenticated hybrid handshake completion. P1 regression/static guards now cover swapped identities, mismatched transcripts, and secret-material requirements. |
| Carriers move opaque HYDRA bytes | README, public API, and message-flow docs say WebRTC/files/HTTP/relays/mailboxes are carriers only. | `HydraEnvelope`, `HandshakeOffer`, `HandshakeAnswer`, carrier examples. | Supported as an API boundary: carriers receive byte buffers, not protocol authority. Metadata remains visible to carriers. |
| Normal path is not inherently anonymous | Public API and message-flow docs distinguish key/session messaging from anonymous designs. | Contacts, identities, sessions, contact cards. | Correctly documented. Normal conversations are contact/session based. |
| Anonymous to the other user | Public docs say use a one-time HYDRA identity/contact card for that chat. | `generate_id`, `create_contact_card`, `add_contact`. | Possible manually today by creating a fresh identity/card. First-class one-time API remains P4 work. |
| Unlinkable across chats | Public docs say use fresh identities/cards/invites/mailboxes/app handles. | Identity/contact/lobby invite APIs. | Possible only by app discipline today. First-class unlinkability helpers remain P4/P5 work. |
| Anonymous to relay/server | Public docs say relays only need opaque bytes but may see timing/IP/routing metadata. | Carrier boundary, `HydraEnvelope`, lobby recipient hints. | Correctly documented. HYDRA encryption does not hide relay-observable metadata. |
| Anonymous to network | Public docs say Tor/I2P/mixnet/proxy/relay design is required. | Outside HYDRA facade. | Unsupported by HYDRA encryption alone; must stay documented as carrier/network-layer work. |
| Anonymous-but-authorized | Public docs say proofs/blind credentials/tokens are separate. | No current facade implementation. | Unsupported until P6. |
| Local state confidentiality | Public API states `state-v1.hydra` is authenticated-encrypted and requires a state password before local state opens. | `storage.rs`, `codec/storage.rs`, `codec/messages.rs`, `codec/contacts.rs`, `codec/lobbies.rs`, `codec/identity.rs`. | Supported for normal facade state, with P3 adding per-record scrypt password derivation parameters and random salts. |
| Backup confidentiality | Public API exposes encrypted backup export/import. | `export_backup`, `import_backup`, `codec/storage.rs`. | Supported for backup ciphertext with per-backup scrypt parameters and random salt. |
| Identity password hardening | Public API states password protection uses per-record scrypt parameters and random salts. | `codec/identity.rs`, `codec/storage.rs`. | Supported for current facade identity records, normal state, and backups through scrypt-derived wrapping keys. Weak passwords remain vulnerable to offline guessing. |
| Contact card metadata | Public API states default cards expose the public verification key only, with explicit labeled cards for label sharing. Contact id/fingerprint and safety code are derived locally. | `contacts.rs`, `codec/contacts.rs`. | Supported in P4 with minimized default cards and first-class one-time contact-card helpers. |
| Lobby invite metadata | Public API states default invites expose lobby id and max-member policy only, with explicit labeled/member-list invite helpers when apps intentionally need more metadata. | `lobbies.rs`, `codec/lobbies.rs`. | Supported in P4 with minimized default invites and first-class one-time lobby-invite helpers. |
| Lobby recipient tag | Public API now states `HydraLobbyEnvelope.recipient()` is a routing hint, not anonymous routing. | `lobbies.rs`. | Correctly bounded. P5 owns hardening/blinded tag options. |

## Boundary definitions

### Anonymous to the other user

Meaning: the peer does not receive a stable identity/contact card that links back to the user's ordinary identity.

Current implementation path: call `create_one_time_contact_card`, which creates a fresh identity, makes it active, and returns a minimized contact card for that chat.

Invariant: public docs must not imply the normal long-lived contact/session path is anonymous.

Unsupported until later phases: automatic cleanup and app-level UX that prevents accidental reuse after a one-time card has been used.

### Unlinkable across chats

Meaning: two separate chats/lobbies cannot be linked by reused HYDRA cards, lobby invites, mailbox IDs, app account IDs, or carrier metadata.

Current implementation path: supported through first-class one-time contact-card and lobby-invite helpers plus app-controlled fresh carrier/mailbox identifiers.

Invariant: public docs must state that reuse links chats.

Unsupported until later phases: automatic cleanup after one-time invite/card use and carrier mailbox alias guidance.

### Anonymous to relay/server

Meaning: a relay or mailbox server does not need HYDRA plaintext, identity secrets, or session keys to carry messages.

Current implementation path: app sends opaque handshake/envelope bytes through the relay. Relays may still observe timing, IP addresses, request sizes, mailbox IDs, recipient tags, and app-level routing data.

Invariant: relay opacity must never be described as full relay anonymity.

Unsupported until later phases: relay metadata minimization, blinded mailbox aliases, and anonymous-but-authorized relay access.

### Anonymous to network

Meaning: network observers cannot link endpoints, IPs, timing, or traffic patterns.

Current implementation path: none inside HYDRA. This requires Tor, I2P, a mixnet, proxy routing, or another carrier/network privacy design.

Invariant: HYDRA encryption must not be documented as hiding endpoints or traffic analysis.

### Anonymous-but-authorized

Meaning: a user proves eligibility to a lobby, mailbox, relay, or paid/rate-limited service without revealing a stable HYDRA identity.

Current implementation path: none. Plain contact cards authenticate keys; they are not unlinkable authorization credentials.

Invariant: authorization tokens/proofs must stay separate from message encryption and contact identity.

## Existing evidence and tests

| Existing evidence | File/path | Covered property |
|---|---|---|
| Tampered offer/answer rejection test | `crates/hydra-msg/src/tests.rs` | Signed authenticated hybrid handshake rejects modified public bytes. |
| Swapped identity answer rejection test | `crates/hydra-msg/src/handshake_tests.rs` | Initiator refuses an answer signed by a different identity than the pending contact. |
| Mismatched answer transcript rejection test | `crates/hydra-msg/src/handshake_tests.rs` | Initiator refuses an answer rebound to another offer nonce/transcript. |
| Facade handshake static privacy guard | `qa/ci/check-privacy-invariants.*` | Official validation requires ML-DSA signing/verification, X25519 secret input, ML-KEM secret input, answer confirmation, and no reintroduced public transcript-only helper. |
| Metadata minimization regression tests | `crates/hydra-msg/src/tests.rs` | Default contact cards omit labels/ids/safety strings, default lobby invites omit labels/member lists, and one-time helpers produce fresh ids. |
| Metadata minimization static privacy guard | `qa/ci/check-privacy-invariants.*` | Official validation requires current V1 minimized card/invite formats and one-time helper APIs. |
| Contact handshake and attachment roundtrip | `crates/hydra-msg/src/tests.rs` | Post-handshake facade send/receive carries encrypted envelopes and restores plaintext locally. |
| Encrypted backup wrong-password test | `crates/hydra-msg/src/tests.rs` | Backup ciphertext requires the backup password before import succeeds. |
| Encrypted state persistence test | `crates/hydra-msg/src/storage_tests.rs` | Confirms current state persists inside authenticated-encrypted `state-v1.hydra` without plaintext message/contact/attachment leakage. |
| Lobby recipient-tagged envelope test | `crates/hydra-msg/src/tests.rs` | Confirms the recipient tag is a routing helper on per-member envelopes. |
| Public docs anonymity wording | README, public API, message-flow docs | Distinguishes anonymous-to-user, unlinkable-across-chats, relay opacity, network anonymity, and anonymous authorization. |
| Docs/static gate | `qa/ci/check-docs.sh`, `qa/ci/check-tests.ps1` | Blocks public roadmap links and stale privacy wording regressions. |

## Unsupported properties that must stay marked as future work

- First-class one-time contact-card and one-time lobby-invite APIs.
- Automatic unlinkability protection across chats/lobbies/mailboxes.
- Anonymous network transport.
- Anonymous-but-authorized access control.
- Blinded/randomized lobby routing tags or mailbox aliases.
- Independent cryptographic audit or enterprise production certification.

## P1 conclusion

P1 closes the known facade-handshake confidentiality verification gap, but does not make the repository production-ready or enterprise-grade. The remaining implementation privacy gaps are metadata minimization, routing privacy, and anonymous authorization:

```text
- content encryption and carrier opacity are implementation-backed after session establishment;
- local state at rest is always AEAD-sealed in `state-v1.hydra` with a required state password;
- password-derived protection now uses scrypt, but weak user passwords remain a risk;
- metadata in contact cards and lobby invites is minimized by default, expanded only through explicit labeled/member APIs, and recipient tags remain intentional visible routing hints;
- network anonymity and anonymous authorization are separate designs, not HYDRA encryption properties.
```
