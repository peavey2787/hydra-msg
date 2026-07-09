# HYDRA-MSG implementation privacy roadmap

This is an internal implementation roadmap for the current privacy-hardening pass. It is intentionally not part of public README navigation because it can be replaced whenever the active engineering plan changes.

Current focus: close the implementation privacy gaps that remain after the authenticated hybrid facade handshake work, then prove the public facade, local storage, identity vault, contact-card, lobby, and carrier-facing boundaries match the privacy claims in the spec docs.

## Rules and guidelines

1. **Privacy claims must match implementation.** Do not document a stronger privacy property than the code actually provides.
2. **Encryption confidentiality must not depend on public transcript material alone.** Session keys must include private/ephemeral key agreement material and authenticated transcript binding.
3. **Separate content privacy from metadata privacy.** Message encryption, relay opacity, network anonymity, and unlinkability are different properties and must be implemented and documented separately.
4. **Default storage should be safe if copied.** Normal local state should not expose plaintext messages, attachments, identity seeds, lobby membership, or contact metadata to offline readers.
5. **Passwords require memory-hard protection.** Any password-derived storage key must use a modern memory-hard KDF with per-record salt and stored parameters.
6. **Metadata exposure must be intentional.** Contact cards, lobby invites, member lists, labels, recipient tags, mailbox IDs, and carrier routing hints must either be minimized, one-time scoped, encrypted, or explicitly documented as visible.
7. **One-time privacy tools must be first-class.** Users and apps need simple APIs for one-time identities, one-time contact cards, one-time lobby invites, and unlinkable mailbox/routing setup.
8. **Do not break the public facade casually.** Keep the current `hydra-msg` public API stable unless a privacy bug requires an explicit migration or version bump.
9. **Migrations must be safe and testable.** Any state format change needs versioned decoding, upgrade tests, rollback/failure handling, and no silent data loss.
10. **Keep artifacts out of the repo root.** Generated state, logs, audits, scratch output, and validation notes belong under `target/` or `docs/project/audit/` as appropriate.
11. **Use one official validation path.** `qa/ci/check-all.*` must keep running tests, examples, docs, Markdown links, lock checks, and source-size guardrails.
12. **Before marking complete, ask:** Is this production-ready? Is it enterprise-grade? Are the privacy boundaries correct? If not, record what remains.

## Phases and steps

### P0 — Privacy baseline and invariant map

Goal: define exactly what each layer promises before changing storage and metadata behavior.

Steps:

- Inventory public privacy claims in `README.md`, `docs/spec/`, `docs/impl/`, and `docs/validation/`.
- Map each claim to the implementation files that enforce it.
- Record explicit boundaries for:
  - anonymous to the other user,
  - unlinkable across chats,
  - anonymous to relay/server,
  - anonymous to network,
  - anonymous-but-authorized.
- Add tests or audit notes for the privacy properties that already exist.
- Mark unsupported properties as future work instead of implying they are automatic.
- Confirm no public docs point users to this internal roadmap.

### P1 — Facade handshake confidentiality verification

Goal: ensure the public `hydra-msg` facade handshake uses real authenticated hybrid key agreement and cannot fall back to public transcript-derived secrets.

Steps:

- Verify `init_handshake`, `reply_handshake`, and `finish_handshake` use authenticated hybrid material, not public nonce/id material alone.
- Keep ML-DSA identity signatures bound to the offer/answer transcript.
- Keep ephemeral X25519 contribution in the session secret.
- Keep ephemeral ML-KEM contribution in the session secret.
- Keep answer confirmation before the initiator installs a session.
- Add regression tests proving tampered offers, tampered answers, swapped identities, and mismatched transcripts fail.
- Add a negative test or static guard preventing any reintroduction of public-only secret derivation.
- Update benchmark notes so facade-handshake numbers are regenerated after the real hybrid path.

### P2 — Encrypted local state at rest

Goal: stop normal `state-v1.hydra` files from storing plaintext messages, attachments, identities, contacts, lobbies, and routing metadata.

Steps:

- Design a versioned encrypted state format, tentatively `state-v2.hydra`.
- Separate public header fields from encrypted payload fields.
- Seal message bodies, attachment bytes, identity records, contact records, lobby records, and session material.
- Authenticate the whole state file, including version and KDF parameters.
- Keep only the minimum safe plaintext header needed for format detection and migration.
- Add migration from plaintext `state-v1.hydra` to encrypted `state-v2.hydra`.
- Ensure migration deletes or archives plaintext state only after successful encrypted write and fsync/rename.
- Add tests for wrong password, corrupted ciphertext, truncated file, replayed old file, and partial migration failure.
- Update backup/export behavior so backups and normal state use consistent authenticated encryption rules.

### P3 — Enterprise-grade password KDF hardening

Goal: replace cheap password hashing/HKDF-only password protection with a memory-hard KDF and versioned parameters.

Steps:

- Choose Argon2id unless dependency, platform, or WASM constraints require scrypt as a fallback.
- Store per-record random salts and explicit KDF parameters.
- Add KDF profile names for interactive, mobile, and high-security settings.
- Use the KDF output only as key material for authenticated encryption or wrapping keys.
- Migrate existing identity records and state files to the new KDF format.
- Keep old-format decoding only long enough to migrate safely.
- Add tests proving identical passwords produce different stored records because salts differ.
- Add tests for wrong password, changed KDF parameters, legacy import, and re-encryption after password change.
- Document that weak user passwords still limit offline resistance.

### P4 — Contact-card and invite metadata minimization

Goal: make metadata exposure in contact cards and lobby invites intentional, minimized, and easy to avoid for unlinkable use cases.

Steps:

- Audit exactly what current contact cards expose: label, public key, contact id, identity id, and any stable routing data.
- Audit exactly what current lobby invites expose: lobby id, member list, policy, labels, and routing hints.
- Add one-time contact-card generation as a first-class facade/API path.
- Add one-time lobby invite generation as a first-class facade/API path.
- Support label minimization, such as empty labels, local-only labels, or encrypted labels where practical.
- Ensure docs clearly state that reusing contact cards links chats.
- Ensure docs clearly state that fresh identities/contact cards are required for unlinkability across chats/lobbies.
- Add tests showing one-time cards/invites produce fresh ids and do not reuse stable identifiers unless explicitly requested.

### P5 — Lobby recipient-tag and routing privacy boundary

Goal: make `HydraLobbyEnvelope.recipient()` safe as an explicit app/carrier routing hint without pretending it provides anonymous routing.

Steps:

- Document `recipient()` as a local/app/carrier routing hint, not an anonymity layer.
- Audit whether recipient tags are stable across messages, lobbies, contacts, or devices.
- Add an option for per-lobby or per-message randomized/blinded recipient tags if the carrier can support it.
- Consider opaque mailbox aliases for carrier routing instead of direct contact/lobby-derived tags.
- Ensure recipient hints are not used as cryptographic authentication.
- Add tests proving message authentication does not depend on carrier-provided recipient hints.
- Add tests proving malformed or swapped routing hints do not decrypt as valid messages for the wrong recipient.

### P6 — Anonymous-but-authorized layer design

Goal: plan the separate privacy/auth layer needed when a user must prove authorization without revealing a stable identity.

Steps:

- Define which app flows need anonymous authorization, such as private lobbies, invite-only mailboxes, paid access, or rate-limited relays.
- Decide whether the first implementation should use blind credentials, unlinkable tokens, membership proofs, or a simpler bearer-token stopgap.
- Keep this layer separate from message encryption and contact identity.
- Define replay, double-spend, revocation, and expiry behavior.
- Add a spec note before implementation begins.
- Add tests proving authorization tokens do not become stable cross-chat identifiers.

### P7 — Validation, docs, and production-readiness gate

Goal: prove the implementation privacy boundaries are correct and stay correct.

Steps:

- Run `qa/ci/check-all.sh` and `qa/ci/check-all.ps1` after each completed implementation phase.
- Ensure every example package remains covered by `check-examples.*`.
- Add parser/codecs fuzz targets for state files, contact cards, lobby invites, handshakes, and message envelopes.
- Add fixture tests for legacy state migration.
- Add documentation tests or static checks for privacy-boundary wording.
- Add an audit checklist under `docs/project/audit/` for implementation evidence.
- Re-run facade and mobile performance benchmarks after encryption-at-rest and KDF changes.
- Perform a final production-ready and enterprise-grade audit before declaring completion.

## Success criteria

This roadmap succeeds when:

1. The public facade handshake cannot derive session keys from public transcript material alone.
2. Normal local state files are encrypted and authenticated at rest.
3. Identity password protection uses a memory-hard KDF with stored salts and parameters.
4. Backups, state files, and identity exports have consistent authenticated encryption behavior.
5. Contact cards and lobby invites have documented visible metadata and first-class one-time/unlinkable alternatives.
6. Lobby recipient tags are documented and tested as routing hints, not anonymous routing.
7. Anonymous-to-network and anonymous-but-authorized properties are explicitly separated from HYDRA encryption.
8. Migration tests prove existing users can upgrade without silent data loss.
9. `qa/ci/check-all.*` passes, including tests, examples, docs, Markdown links, lock checks, and file-size guardrails.
10. A final audit records whether the repo is production-ready and enterprise-grade.

## Progress report

### Completed before this roadmap

- Public facade handshake was replaced with an authenticated hybrid handshake path using ML-DSA transcript signatures, ephemeral X25519, ephemeral ML-KEM, and answer confirmation.
- `check-examples.*` was expanded so every current package under `examples/` is part of the official examples gate.
- Public docs were updated to distinguish anonymous-to-user, unlinkable-across-chats, anonymous-to-relay, anonymous-to-network, and anonymous-but-authorized privacy boundaries.
- Public README navigation was cleaned so this internal roadmap is not part of public navigation.

### Completed in P0

- Added a maintainer privacy baseline and invariant map under `docs/project/audit/privacy-baseline-invariant-map.md`.
- Inventoried the current public privacy claims and mapped them to the facade implementation files that enforce or expose each boundary.
- Recorded explicit boundaries for anonymous-to-user, unlinkable-across-chats, anonymous-to-relay/server, anonymous-to-network, and anonymous-but-authorized designs.
- Marked unsupported implementation properties as future work instead of implying they are automatic: encrypted state at rest, memory-hard KDFs, first-class one-time cards/invites, network anonymity, anonymous authorization, and blinded routing tags.
- Updated public-facing privacy-boundary wording in the README, public developer API, message-flow docs, and production QA gate.
- Reconfirmed that public docs must not point users to this internal roadmap.

### Current known gaps

- The authenticated hybrid facade handshake still needs the regression/static-guard tests listed in P1 before the gap should be considered permanently closed.
- Normal local state remains plaintext at rest until P2 is implemented.
- Identity password protection still needs memory-hard KDF hardening until P3 is implemented.
- Contact cards and lobby invites still expose intentional metadata and need first-class one-time/unlinkable API support.
- Lobby recipient tags remain routing hints and do not provide anonymous routing.
- Anonymous-to-network requires a carrier/network layer such as Tor, I2P, mixnet, proxy, or a relay design that hides IP/timing metadata.
- Anonymous-but-authorized requires a separate auth/privacy layer such as proofs, blind credentials, or unlinkable tokens.

### Active phase

- P1 verification/regression hardening is ready to start.

### Not started

- P1 verification/regression hardening.
- P2 encrypted local state at rest.
- P3 memory-hard password KDF migration.
- P4 one-time contact-card and invite metadata minimization.
- P5 lobby recipient-tag privacy boundary hardening.
- P6 anonymous-but-authorized design.
- P7 final validation and production-readiness audit.
