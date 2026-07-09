# P7 privacy hardening production-readiness audit

Status: P7 audit complete after privacy-hardening phases P0 through P6.

This is maintainer evidence for the active privacy-hardening roadmap. It is not public product documentation and is intentionally kept under `docs/project/audit/`.

## Validation scope

P7 reviewed the current HYDRA-MSG facade and app-facing examples after these implementation phases:

- P0 privacy baseline and invariant map;
- P1 authenticated hybrid facade handshake guards;
- P2 encrypted normal local state at rest;
- P3 memory-hard password KDF hardening;
- P4 minimized contact-card and lobby-invite metadata;
- P5 explicit lobby routing privacy boundary;
- P6 one-time anonymous authorization bearer-token stopgap.

The maintainer reported the full local `qa/ci/check-all.sh` gate reached green before this P7 pass, then reported WASM-target dead-code warnings for native-only encrypted-state helpers. P7 fixes those warnings by target-gating native filesystem-state fields and codec helpers instead of allowing or suppressing dead code.

## Production-readiness verdict

HYDRA-MSG is a stronger local release-candidate after this roadmap, but it should not be marketed as enterprise-grade or independently production-certified yet.

Current practical status:

```text
Facade developer API: release-candidate quality after local full validation
Normal message confidentiality after handshake: implementation-backed by authenticated hybrid handshake path
Local state at rest: encrypted/authenticated on native targets with required password
Identity/backup/state password protection: memory-hard scrypt with random salts and stored parameters
Contact-card/lobby-invite defaults: minimized by default, expanded only through explicit APIs
Lobby routing boundary: direct recipient hints are visible metadata; randomized routing hints are available
Anonymous authorization: bounded one-time bearer-token stopgap, not blind credentials or zero-knowledge proofs
Network anonymity: out of scope for HYDRA encryption and requires carrier/network design
Enterprise-grade status: blocked on external evidence and operational hardening below
```

## Privacy boundary audit

| Boundary | Current status | Evidence | Remaining gap |
|---|---|---|---|
| Facade handshake confidentiality | Supported | ML-DSA transcript signatures, ephemeral X25519, ephemeral ML-KEM, answer confirmation, tamper/swap/transcript tests, static privacy guard. | Independent crypto review still absent. |
| Local state confidentiality | Supported on native state files | `state.hydra` is AEAD-sealed with password-derived key and rollback guard. State helpers are target-gated out of browser WASM state builds. | Browser storage persistence remains app responsibility if a browser app chooses to persist state. |
| Password hardening | Supported for current facade state/backup/identity records | scrypt KDF records include profile/parameters/random salts. Privacy guard rejects direct password hashing for storage/identity protection. | Weak user passwords are still guessable; enterprise deployments need password policy or hardware/OS key storage. |
| Contact-card metadata | Supported | Default cards expose public verification key only; labeled and one-time cards are explicit APIs. | Automatic cleanup after one-time use remains app/UX responsibility. |
| Lobby-invite metadata | Supported | Default invites expose lobby id and max-member policy only; labeled/member-list/one-time APIs are explicit. | Lobby id remains visible to invite recipients by design. |
| Lobby routing metadata | Supported as a documented boundary | `recipient()` is direct app-local routing metadata; `routing_hint()` is randomized per encrypted copy. | Anonymous routing still requires carrier design. |
| Anonymous-to-relay | Partially supported | Carriers move opaque bytes and do not need plaintext/session keys. | Timing, IP, size, mailbox, and routing metadata can still leak. |
| Anonymous-to-network | Not provided by HYDRA encryption | Public docs separate this from message encryption. | Requires Tor, I2P, mixnet, proxy, relay, or other network privacy layer. |
| Anonymous-but-authorized | Bounded stopgap | One-time bearer tokens with scope/action/expiry/nullifier/replay rejection. | Blind issuance, zero-knowledge eligibility, and enterprise credential review remain future work. |

## CI and guardrail audit

Official validation now includes these layers through `qa/ci/check-all.*`:

```text
check-tests.*
  check-rust.*
  check-rust-file-sizes.*
  check-privacy-invariants.*
  check-docs.*
  check-locks.*
  check-vectors.* unless skipped
check-examples.*
```

The example gate covers every current package under `examples/`, including app-core/app examples and the WASM-backed browser examples. The docs gate checks navigation ownership and relative Markdown links. The privacy-invariant gate blocks known regressions for handshake material, encrypted state, password KDFs, metadata minimization, lobby routing, anonymous authorization, and accidental facade/app format version tags.

## Warnings fixed in P7

The WASM example build reported dead-code warnings for native-only encrypted state helpers:

```text
STATE_MAGIC
Hydra.state_key
Hydra.state_kdf
encode_encrypted_state
decode_encrypted_state
parse_state_kdf
parse_encrypted_state
state_aad
```

P7 fixes this by compiling those fields/helpers only for non-WASM targets. Browser/WASM builds still keep backup export/import and in-memory facade behavior, while native builds keep encrypted filesystem state.

## Enterprise-grade blockers

The following are still required before claiming enterprise-grade production readiness:

1. Independent cryptographic review of the facade handshake, state encryption, KDF use, authorization tokens, and lower-level protocol proofs.
2. Parser/fuzzing campaign for state files, backups, contact cards, lobby invites, auth tokens, handshakes, and envelopes.
3. Cross-platform runtime evidence for Linux, Windows, macOS, and browser/mobile WASM.
4. Dependency advisory/license policy through `cargo audit`, `cargo deny`, or equivalent tooling.
5. SBOM and signed release packaging process.
6. Browser persistent-state design if the WASM facade is used as a real app SDK instead of a demo/runtime component.
7. External interoperability evidence or a second implementation for protocol-standard claims.
8. Network anonymity carrier design if anonymous-to-network is a product requirement.
9. Blind credential or zero-knowledge authorization design if anonymous-but-authorized must avoid issuer/verifier linkability beyond the current one-time bearer-token stopgap.
10. Operational security guidance for backups, password quality, key export, incident response, and recovery.

## P7 conclusion

P7 completes the current implementation privacy-hardening roadmap as a local release-candidate audit. The repository can be treated as substantially improved and internally consistent after a fresh local `qa/ci/check-all.sh` or `qa/ci/check-all.ps1` pass.

It should not be described as enterprise-grade, independently audited, network-anonymous, or backed by blind credentials/zero-knowledge authorization until the external evidence and future-work items above are completed.
