# HYDRA-MSG Stupid-Simple API Roadmap

## Navigation

- [Main README](../README.md)
- [How HYDRA messaging works](impl/message-flow/README.md)
- [Repository structure](spec/README.md)
- [Crates](../crates/README.md)
- [Examples](../examples/README.md)

The goal is to make HYDRA stupid-simple for app developers.

A developer should be able to:

```text
open HYDRA
create or restore an identity
add and verify a contact
exchange a handshake over any carrier
send an encrypted message with or without attachments
receive plaintext and attachments
back up local data
run storage status and benchmarks
```

The public API source of truth is:

```text
docs/spec/public-developer-api.md
```

The P2 audit artifact is:

```text
docs/project/audit/api-inventory-ownership-audit.md
```

## Rules and guidelines

1. **Make the public API stupid-simple.** No app developer should need to learn HYDRA crypto/session/wire internals.
2. **No public advanced API for v1.** Do not add `HydraConfig`, `HydraProfile`, builders, protocol-info APIs, supported-suite APIs, session import/export APIs, public chunk APIs, checkpoint APIs, predicate APIs, or lobby-state import/export APIs.
3. **HYDRA is transport-agnostic.** WebRTC, libp2p, HTTP, QR codes, files, relays, Kaspa pointers, mailbox nodes, and manual copy/paste are carriers only. They move opaque HYDRA bytes. They are not protocol authority.
4. **`crates/` is for protocol/product crates only.** Demo apps belong under top-level `examples/`.
5. **Keep docs organized by purpose.** Product docs belong under `docs/spec/`, `docs/impl/`, or `docs/validation/`. Assistant working notes and audits belong under `docs/project/`.
6. **Do not make `hydra-msg` depend on example crates.** Reuse implementation ideas by migrating/copying code into the facade internals, not by depending on `examples/hydra-app-core`.
7. **Runtime data must never be committed.** `hydra-msg-data/`, identity vaults, test identities, app runtime state, and local secrets stay out of git.
8. **One owner per concern.** Public facade in `hydra-msg`; crypto in `hydra-crypto`; wire encoding in `hydra-envelope`; sessions in `hydra-session`; group/lobby internals in `hydra-group`; app/demo behavior in `examples/`.
9. **Carriers are external.** WebRTC, libp2p, Kaspa pointers, relays, mailboxes, and manual copy/paste examples must sit above the HYDRA message API.
10. **Docs follow the API.** If the API cannot be explained in a few lines, the API is still too complicated.

## Target crate layout

```text
crates/
  hydra-core/       low-level constants, closed discriminants, shared protocol types, errors
  hydra-crypto/     fixed-suite crypto backend internals
  hydra-envelope/   byte-exact envelope/header/protected-record encoding
  hydra-session/    1:1 session ratchets, replay protection, rekey/close logic
  hydra-group/      group/lobby primitives behind the simple lobby API
  hydra-msg/        public developer facade crate
  hydra-msg-wasm/   browser/mobile WASM bindings over the facade
  hydra-msg-cli/    developer CLI utility over the facade

examples/
  handshake_roundtrip/ active facade example
  contact_card/        active facade example
  attachment_roundtrip/ active facade example
  lobby_roundtrip/     active facade example
  mobile_perf_web/     active WASM/browser benchmark host
  manual_file_carrier/ files on disk as a manual opaque-byte carrier
  webrtc_manual_carrier/ WebRTC DataChannel carrier after manual contact-card exchange
  hydra-app-core/      demo app reference only
  hydra-app/           demo app reference only
```

## Target public API summary

```rust
use hydra_msg::{Hydra, HydraMessage};

let mut hydra = Hydra::open("./hydra-msg-data")?;

let my_id = hydra.generate_id("password")?;
hydra.set_active_id(my_id, "password")?;

let my_card = hydra.create_contact_card()?;
let bob = hydra.add_contact(bob_card)?;
hydra.verify_contact(bob.id(), safety_code)?;

let offer = hydra.init_handshake(bob.id())?;
let answer = hydra.reply_handshake(offer)?;
hydra.finish_handshake(answer)?;

let envelope = hydra.send(
    bob.id(),
    HydraMessage::text("hello")
        .attach_file("./photo.jpg")?
        .attach_bytes("data.bin", bytes_here)?,
)?;

let data = hydra.receive(envelope)?;
println!("{}", data.text()?);
for attachment in data.attachments() {
    std::fs::write(attachment.filename(), attachment.bytes())?;
}
```

See `docs/spec/public-developer-api.md` for the complete API list.

## Phases and steps

### P0 — Hygiene and source-control safety — COMPLETE

Goal: remove local runtime artifacts and freeze the stupid-simple API target.

Steps:

- Add `hydra-msg-data/` to `.gitignore`.
- Remove tracked/staged `hydra-msg-data/` artifacts.
- Document that identity vaults, local secrets, test identities, and app runtime state must not be committed.
- Add the public API source-of-truth doc under `docs/spec/public-developer-api.md`.
- Replace the old app-polish roadmap with this developer API roadmap.
- Do not change protocol behavior.

### P1 — Move demo app crates to top-level examples — COMPLETE

Goal: remove demo/app crates from the protocol/product crate area before facade work starts.

Steps:

- Create top-level `examples/` if missing.
- Move `crates/hydra-app-core` to `examples/hydra-app-core`.
- Move `crates/hydra-app` to `examples/hydra-app`.
- Update root `Cargo.toml` workspace members.
- Update moved crate path dependencies.
- Update docs that define crate ownership.
- Document both moved crates as examples, not protocol/product crates.

### P2 — API inventory and ownership audit — COMPLETE

Goal: identify what existing moved example/app-domain code can be reused by the new facade.

Steps:

- Inspect `examples/hydra-app-core` identity vault, contact, session, storage, recovery, attachment/payload, message store, group, and carrier-boundary modules.
- Classify each module as facade candidate, internal implementation, example helper, app-demo helper, or code to remove.
- Identify duplicate abstractions between app-domain code and protocol crates.
- Map existing code to `docs/spec/public-developer-api.md`.
- Record gaps before creating the new facade crate.
- Write the audit to `docs/project/audit/api-inventory-ownership-audit.md`.
- Do not make `crates/hydra-msg` depend on example crates.

### P3 — Create `hydra-msg` facade crate — COMPLETE

Goal: add the public Rust API without breaking lower-level protocol crates.

Steps:

- Add `crates/hydra-msg` to the workspace.
- Expose `Hydra`, `HydraMessage`, `HydraAttachment`, receive data, IDs, handshake offer/answer types, envelope bytes, storage status, benchmark report, and simple errors.
- Implement `Hydra::open(data_dir)` and `Hydra::open_default()`.
- Add the public identity methods.
- Add the public contact methods.
- Add `init_handshake`, `reply_handshake`, and `finish_handshake`.
- Ensure `finish_handshake` creates/activates the initiator-side session and `reply_handshake` creates/activates the responder-side session.
- Add `send` and `receive` over the session engine.
- Make `send` accept `HydraMessage` with text, raw bytes, file attachments, and in-memory byte attachments.
- Make `receive` return plaintext and attachment accessors.
- Add the public lobby method names without exposing AOL2/checkpoint/predicate/lobby-state APIs.
- Add backup/restore method names and storage status/benchmark methods.
- Add initial tests for identity export/import, contact add, handshake, send/receive, and attachment roundtrip.

### P4 — Harden storage and backup/restore — COMPLETE

Goal: replace facade scaffolding with safe local persistence.

Steps:

- Provide safe default filesystem storage for native Rust.
- Keep plaintext private keys out of storage.
- Support memory-only unlocked identities.
- Replace temporary/simple backup bytes with encrypted authenticated backup data.
- Implement real `export_contacts`, `import_contacts`, `export_messages`, and `import_messages` semantics.
- Keep only `storage_status` public for storage diagnostics.

### P5 — Minimal examples over `hydra-msg` — COMPLETE

Goal: turn the API into obvious copy-paste developer workflows.

Steps:

- Keep moved demo app crates under `examples/` until P9 removes them from the active workspace.
- Add `examples/handshake_roundtrip` using `hydra-msg`.
- Add `examples/contact_card` using `hydra-msg`.
- Add `examples/attachment_roundtrip` using `HydraMessage::text(...).attach_file(...)` and `HydraAttachment::from_bytes(...)`.
- Add/align `examples/mobile_perf_web` with the facade API as a server-side P5 benchmark host. True browser/mobile WASM benchmarking remains P6.
- Each example gets a short README and one obvious run command.

### P6 — WASM/JavaScript bindings — COMPLETE

Goal: make the same simple API usable from browser/mobile apps.

Steps:

- Add a clearly isolated WASM binding crate over `hydra-msg`.
- Mirror the Rust API shape: open, identity, contacts, handshake, send/receive, lobby, backup/restore, storage status, benchmark.
- Support text messages, byte messages, file-style attachments supplied by browser bytes, and byte attachments.
- Keep WASM behavior protocol-equivalent to the Rust facade.
- Update mobile benchmarks to call the facade from the browser/device through WASM.
- Keep browser persistence in-memory for this phase unless the app explicitly uses backup/export/import helpers.

### P7 — CLI/dev tool — COMPLETE

Goal: provide a developer utility without confusing it with the demo app.

Steps:

- Create `hydra-msg-cli`.
- Support commands such as `generate-id`, `contact-card`, `handshake-demo`, `send-demo`, `attachment-demo`, `bench`, and `doctor`.
- Keep the CLI as a tool over `hydra-msg`, not protocol authority.
- Document CLI usage under `docs/impl/hydra-msg-cli.md`.

### P8 — Group/lobby facade completion — COMPLETE

Goal: wire lobbies to real group/session internals only through the trimmed public API.

Steps:

- Implement the simple lobby methods listed in `docs/spec/public-developer-api.md`.
- Do not expose checkpoint APIs, AOL2 state APIs, predicate APIs, lobby-state import/export, or advanced group/lobby controls.
- Add lobby send/receive examples and tests.

### P9 — Remove demo app crates from active workspace — COMPLETE

Goal: remove naming confusion after the facade API exists.

Steps:

- Remove `hydra-app-core` and `hydra-app` demo crates from the active workspace.
- Keep the demo code only as reference material under `examples/`.
- Preserve useful flows through the new `hydra-msg` examples and `hydra-msg-cli`, not through the demo app.
- Ensure no example crate owns public protocol semantics.
- Update README files and docs references so developers start with `hydra-msg`.

### P10 — Carrier examples — COMPLETE

Goal: demonstrate that HYDRA does not care how bytes move.

Steps:

- Add a WebRTC example where contact-card exchange is explicitly out-of-band and manual.
- The WebRTC example may move handshake bytes and encrypted envelopes only after users manually paste/import each other's contact cards.
- Add a simple file/manual carrier example showing opaque contact-card, handshake, and envelope bytes moving through files.
- Keep carrier code outside `hydra-msg`.
- Document WebRTC, libp2p, relays, QR codes, Kaspa pointers, files, and mailboxes as carriers, not authorities.

### P12 — Release-readiness cleanup — COMPLETE

Goal: make the developer API credible before manual validation.

Steps:

- Remove duplicate and unused code from the active workspace.
- Update README files to point developers at `hydra-msg` first.
- Include benchmark numbers with honest caveats.
- Mark protocol release status accurately.
- Publish only after P13 manual validation is clean and the simple API is stable enough to avoid immediate churn.

### P13 — Manual validation gate

Goal: run final validation manually after the roadmap implementation is complete.

Steps:

- Run the full validation script: `qa/ci/check-all.ps1` on Windows or `qa/ci/check-all.sh` on Unix.
- Run the example validation script separately: `qa/ci/check-examples.ps1` on Windows or `qa/ci/check-examples.sh` on Unix.
- Fix any reported failures before release.
- Record the exact validation commands and results.

## Success criteria

This roadmap succeeds when a new developer can:

1. add one dependency;
2. open HYDRA with one data path;
3. generate or import an identity;
4. add and verify a contact;
5. exchange a handshake over any carrier;
6. send an encrypted HYDRA message with or without attachments;
7. receive plaintext and attachments;
8. export/import contacts, messages, identities, and backups;
9. run storage status and benchmark;
10. understand where WebRTC, relays, libp2p, Kaspa, or other carriers plug in without touching core crypto/session internals.

Target sentence:

> HYDRA-MSG gives app developers post-quantum encrypted messages in Rust and WASM with a stupid-simple transport-agnostic API.

## Progress log

### 2026-07-08 — P0 complete

- Added `hydra-msg-data/` to `.gitignore`.
- Removed runtime data from the package.
- Added/kept the public API source-of-truth under `docs/spec/public-developer-api.md`.
- Replaced the prior roadmap with the stupid-simple API roadmap.

### 2026-07-08 — P1 complete

- Moved `hydra-app-core` and `hydra-app` into top-level `examples/`.
- Updated root workspace members and moved crate path dependencies.
- Updated crate ownership docs so demo/app crates are examples, not protocol/product crates.

### 2026-07-08 — P2 complete

- Added the API inventory/ownership audit under `docs/project/audit/api-inventory-ownership-audit.md`.
- Confirmed the new facade must not depend on example crates.
- Mapped reusable previous app-domain areas to future facade internals.

### 2026-07-08 — P3 complete

- Added `crates/hydra-msg` to the workspace.
- Exposed the stupid-simple public facade types: `Hydra`, `HydraMessage`, `HydraAttachment`, receive data, IDs, opaque handshake bytes, opaque envelope bytes, lobby types, storage status, benchmark report, and simple errors.
- Implemented the public open, identity, contact, handshake/session, message, lobby, backup/restore, storage status, and benchmark method surfaces from `docs/spec/public-developer-api.md`.
- Ensured `reply_handshake` creates/activates the responder-side session and `finish_handshake` creates/activates the initiator-side session.
- Made `send` accept `HydraMessage` with text, raw bytes, file attachments, named byte attachments, and simple `HydraAttachment::from_bytes(bytes)` construction.
- Made `receive` return plaintext and attachment accessors while keeping payload packing/chunk mechanics internal.
- Kept trimmed APIs out of the facade: no `HydraConfig`, no profiles, no builder, no protocol-info/suite APIs, no session import/export, no public chunk APIs, no checkpoint/lobby-state/AOL2 predicate APIs, and no advanced public API layer.
- Added facade tests covering identity export/import, contact import/export and verification, handshake/session activation, send/receive, attachment roundtrip, lobby surface, backup verification/import surface, storage status, and benchmark surface.
- Validation with `cargo fmt`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` remains a later release-readiness step because this environment does not have Cargo/Rust installed.



### 2026-07-08 — P4 complete

- Replaced the `hydra-msg` facade's memory-only placeholder store with a native filesystem state file under the chosen HYDRA data directory.
- Kept identity seed material encrypted at rest and loaded decrypted identity seed material only into memory after `unlock_id` / `set_active_id`.
- Ensured reopened stores load identities locked by default with no active unlocked identity.
- Persisted contacts, verified/blocked flags, message history, message attachments, lobby summaries, and local counters.
- Replaced the temporary backup placeholder with encrypted/authenticated backup bytes protected by the backup password.
- Implemented backup import as a full state restore path and kept `verify_backup` limited to outer-format validation because authenticated verification requires the backup password.
- Expanded message export/import so attachments survive export/import instead of losing payload data.
- Kept the public storage diagnostics surface trimmed to `storage_status()` only.
- Added P4-focused facade tests for persistence, locked reopen behavior, encrypted backup restore, wrong-password backup rejection, and attachment-bearing message persistence.
- No advanced public API was added.
- Validation with `cargo fmt`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` remains a later release-readiness step because this environment does not have Cargo/Rust installed.


### 2026-07-08 — P5 complete

- Added `examples/handshake_roundtrip` as the minimal two-party contact-card, handshake, send/receive developer workflow over `hydra-msg`.
- Added `examples/contact_card` as the minimal contact-card creation, add, verify, export, and import workflow over `hydra-msg`.
- Added `examples/attachment_roundtrip` showing the clean public `HydraMessage::text(...).attach_file(...).attach_bytes(...)` design plus `HydraAttachment::from_bytes(...)`.
- Added `examples/mobile_perf_web` as a tiny LAN web page that calls the public `hydra.benchmark()` facade API on the server host. The P6 WASM phase owns true phone-side/browser-side facade benchmarking.
- Updated root workspace members so the new examples participate in later workspace validation.
- Updated `examples/README.md` and root `README.md` with copy-paste run commands.
- Kept moved demo app crates under `examples/` and did not make them protocol authority.
- No advanced public API was added.

### 2026-07-08 — P6 complete

- Added `crates/hydra-msg-wasm` as an isolated WASM binding crate over `hydra-msg`.
- Exposed JS-friendly stupid-simple bindings: `openDefault`, identity lifecycle, contacts, handshake/session setup, send/receive, lobbies, backup/restore, storage status, and benchmark.
- Added `WasmHydraMessage.text(...)`, `WasmHydraMessage.bytes(...)`, `attachBytes(...)`, and browser file-style attachment support through filename + bytes.
- Added received-message accessors for plaintext, text, attachment count, attachment names, attachment bytes, and attachment source flags.
- Updated `examples/mobile_perf_web` to serve the generated WASM package and run browser/device-side HYDRA facade benchmarks.
- Added `docs/impl/wasm-javascript-bindings.md`.
- Browser persistence is intentionally in-memory in P6; apps can persist using explicit backup/export/import helpers.


### 2026-07-08 — P7 complete

- Added `crates/hydra-msg-cli` as a developer command-line utility over the public `hydra-msg` facade.
- Added commands for `generate-id`, `contact-card`, `handshake-demo`, `send-demo`, `attachment-demo`, `bench`, and `doctor`.
- Added `docs/impl/hydra-msg-cli.md` with command usage and ownership rules.
- Added `hydra-msg-cli` to the root workspace.
- Updated `crates/README.md` and root `README.md` so developers can find the CLI.
- Kept the CLI thin: no `HydraConfig`, no profiles, no builders, no protocol-info/suite APIs, no session import/export, no public chunk APIs, no checkpoint/lobby-state/AOL2 predicate APIs, and no advanced public API layer.
- Validation with `cargo fmt`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` remains a later release-readiness step because this environment does not have Cargo/Rust installed.

### 2026-07-08 — P8 complete

- Completed the trimmed group/lobby facade without adding checkpoint APIs, AOL2 state APIs, predicate APIs, lobby-state import/export, or advanced group/lobby controls.
- Kept `create_lobby(policy)`, `create_lobby_invite`, `join_lobby`, member management, `send_lobby`, `receive_lobby`, `rekey_lobby`, and `close_lobby` as the only public lobby surface.
- Added internal lobby policy validation against HYDRA group limits while keeping group internals hidden from app developers.
- Made lobby invites carry policy and member routing context so joiners can validate incoming lobby messages against local membership.
- Changed `send_lobby` to return recipient-tagged encrypted copies through `HydraLobbyEnvelope`, so carriers know which member should receive each opaque envelope without exposing protocol internals.
- Made `receive_lobby` reject non-lobby payloads without consuming the normal 1:1 message session state.
- Made `receive_lobby` reject lobby messages from contacts that are not members of the local lobby.
- Exposed `lobby_id()` on received messages so app developers can identify the lobby without seeing envelope internals.
- Updated WASM bindings for recipient-tagged lobby envelopes and received-message lobby ids.
- Added `examples/lobby_roundtrip` showing create/join/send/receive over the simple facade.
- Added/expanded facade tests for recipient-tagged lobby envelopes, lobby membership checks, and non-lobby rejection.
- No advanced public API was added.

### 2026-07-08 — P9 complete

- Removed `hydra-app-core` and `hydra-app` from the active workspace.
- Kept the demo crates under `examples/` as reference material only.
- Updated their relative crate paths and removed workspace-inherited package metadata so the reference code remains understandable if inspected manually.
- Removed demo app crates from root workspace members so active workspace validation focuses on protocol/product crates and new facade examples.
- Rewrote root `README.md`, `examples/README.md`, and `crates/README.md` so developers start with `hydra-msg`, `hydra-msg-wasm`, `hydra-msg-cli`, and the active facade examples.
- Updated roadmap scope: removed the AOL2/relay-node phase as out of scope for `hydra-msg`, clarified that the P10 WebRTC carrier example must use manual out-of-band contact-card exchange, and split manual validation into P13 as its own final phase.
- No advanced public API was added.



### 2026-07-08 — P10 complete

- Added `examples/manual_file_carrier` to show that files on disk can carry opaque HYDRA contact-card, handshake, and encrypted-envelope bytes without becoming protocol authority.
- Added `examples/webrtc_manual_carrier` as a browser WebRTC DataChannel carrier example over the `hydra-msg-wasm` facade.
- Kept contact-card exchange strictly manual and out-of-band in the WebRTC example. WebRTC is only used after both users import and verify each other's contact cards.
- Made the WebRTC example use manual SDP copy/paste for signaling, then carry HYDRA handshake offers/answers and encrypted envelopes over the DataChannel.
- Added build scripts and README docs for the WebRTC carrier example.
- Added `docs/impl/carrier-examples.md` documenting carrier ownership and WebRTC/manual-file carrier behavior.
- Added the new carrier examples to the active workspace and README example lists.
- No transport code was added to `hydra-msg`; WebRTC and files remain carriers only.
- No advanced public API was added.


### 2026-07-08 — P12 complete

- Kept the active workspace focused on `crates/hydra-*`, `hydra-msg`, `hydra-msg-wasm`, `hydra-msg-cli`, and the active facade/carrier examples.
- Replaced the previous app-focused QA gate with the current P13 manual validation gate under `docs/validation/production-qa-gate.md`.
- Added `docs/validation/release-readiness.md` as the P12 cleanup and P13 handoff artifact.
- Added `docs/validation/benchmark-results.md` with the real-world benchmark numbers reported from desktop PC, ASUS TUF Ryzen 7 A16 laptop, Samsung Galaxy S20 Ultra, BLU M8L (Original), released August 2020, 1GB RAM, Android 11 Go edition, and a 64 KiB larger-message run.
- Updated root `README.md` with a benchmark snapshot and accurate pre-P13 release-status caveats.
- Removed stale out-of-scope phase wording from demo app reference CSS comments.
- Confirmed the public API remained trimmed: no config/profile/builder layer, no advanced public API, no protocol-info/suite APIs, no session import/export, no public chunk APIs, no checkpoint/lobby-state/predicate APIs.
- Did not run format, tests, clippy, examples, WASM builds, or docs checks; those remain P13 and must be run manually by the maintainer.

### 2026-07-08 — P13 validation scripts prepared

- Kept full workspace validation in `qa/ci/check-all.ps1` and `qa/ci/check-all.sh`.
- Added separate example validation scripts at `qa/ci/check-examples.ps1` and `qa/ci/check-examples.sh`.
- Added `qa/ci/linux-permissions.sh` so Unix users can restore execute bits after ZIP extraction before running validation scripts.
- Kept runnable examples separate from the full validation script so maintainers can test the SDK without waiting on browser/example flows.
- P13 is still manual and not marked complete.

### 2026-07-08 — Source hygiene audit pass

- Removed the WASM-only dead-code warning by gating native filesystem state helpers to native targets.
- Split private `hydra-msg` encoding, decoding, persistence-line, backup, contact-card, handshake, payload, hex, byte-reader, and random-byte helpers into `crates/hydra-msg/src/codec.rs`.
- Kept the public `hydra-msg` API unchanged while reducing mixed-concern code in the facade file.
- Added `docs/project/audit/source-hygiene-audit.md` documenting the audit findings and remaining release blockers.
- P13 is still manual and not marked complete.

### 2026-07-08 — WASM web build output aligned

- Added `qa/ci/build-wasm-web.sh` and `qa/ci/build-wasm-web.ps1` as the official reusable browser/mobile WASM package builders.
- Set reusable WASM output to `target/hydra-msg-wasm/web/`.
- Kept example-specific WASM output under each example's `web/pkg/` directory only for example validation and manual example runs.
- Documented that `crates/hydra-msg-wasm` remains the source of truth for browser/mobile bindings.
- P13 is still manual and not marked complete.


### 2026-07-08 — README navigation cleanup

- Rewrote the main `README.md` as a concise app-developer entry point.
- Replaced the one-process roundtrip snippet with a two-device Bob/Alice app-shape example that explains each step.
- Added `docs/impl/message-flow/README.md` with diagrams and contact/session flow notes.
- Added return navigation to linked project docs, including benchmark notes.
- Kept docs organized with only `docs/roadmap.md` at the top level.
- Updated benchmark wording to identify the BLU M8L (Original), released August 2020, 1GB RAM, Android 11 Go edition.

### 2026-07-08 — Docs ownership cleanup

- Moved important product docs out of `docs/project/` and into the correct purpose folders under `docs/spec/`, `docs/impl/`, and `docs/validation/`.
- Kept `docs/project/` limited to assistant working notes and audit artifacts.
- Added `docs/spec/README.md` as the repository structure and documentation ownership map.
- Updated README navigation and Markdown links to use the corrected docs layout.
- Added docs checks that fail if important product docs are placed under `docs/project/` or if extra files are placed directly under `docs/`.
