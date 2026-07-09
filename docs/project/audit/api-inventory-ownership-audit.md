# HYDRA-MSG API Inventory and Ownership Audit

Status: P2 implementation artifact.

This document records the audit required before creating `crates/hydra-msg`.
The moved demo crates are now examples, and this audit decides what existing
code may be reused behind the future simple public facade.

The public API contract remains:

```text
docs/spec/public-developer-api.md
```

The rule is strict: app developers get one simple `hydra-msg` facade. Anything
that exposes crypto internals, chunk mechanics, envelope classes, rollback
plumbing, GUI behavior, or demo orchestration stays internal or stays in
`examples/`.

## Ownership result

| Area | Existing owner today | Target owner | Decision |
|---|---|---|---|
| Public SDK facade | none | `crates/hydra-msg` | Create next. |
| Protocol constants/types/errors | `crates/hydra-core` | `crates/hydra-core` | Keep low-level. |
| Crypto backend | `crates/hydra-crypto` | `crates/hydra-crypto` | Keep internal to facade. |
| Wire envelope encoding | `crates/hydra-envelope` | `crates/hydra-envelope` | Keep internal to facade. |
| 1:1 ratchet/session engine | `crates/hydra-session` | `crates/hydra-session` | Wrap behind `send`/`receive`. |
| Group/lobby primitives | `crates/hydra-group` | `crates/hydra-group` | Wrap only through simple lobby API when ready. |
| Identity vault/storage | `examples/hydra-app-core` | migrate/copy into `crates/hydra-msg` internals | Reuse implementation ideas, not as an example dependency. |
| Contact cards/trust | `examples/hydra-app-core` and `examples/hydra-app` | migrate/copy into `crates/hydra-msg` internals | Reuse contact-card/safety-number behavior, trim aliases/app commands. |
| Message store/history | `examples/hydra-app-core` | migrate/copy into `crates/hydra-msg` internals | Reuse encrypted local history pieces behind simple methods. |
| Attachment implementation | `examples/hydra-app-core` | internal payload packaging in `crates/hydra-msg` | Public API says attachments; internal API handles chunking/packing. |
| Recovery/backups | `examples/hydra-app-core` | migrate/copy into `crates/hydra-msg` internals | Reuse backup format concepts, expose only simple backup methods. |
| CLI/local GUI | `examples/hydra-app` | `examples/hydra-app` | Stays example/demo only. |
| Carrier helpers/transport demo | `examples/hydra-app-core` | examples or future carrier crates | Do not put carrier authority in `hydra-msg`. |
| Rollback/live-state checks | `examples/hydra-app-core` | internal storage hardening if needed | Do not expose as public v1 API. |
| AOL2/ZK/Kaspa relay behavior | none in HYDRA facade | external projects/examples | Do not add to `hydra-msg` public API. |

## Moved example crate audit

### `examples/hydra-app-core`

| Module | Current role | Facade decision |
|---|---|---|
| `abuse.rs` | App-domain guardrails for invalid commit delivery attempts. | Keep example/app-domain unless a narrow internal validation helper is needed later. No public API. |
| `attachment.rs` | Encrypted attachment objects, manifests, chunk sizing, detached storage helpers. | Convert concepts into internal payload packaging. Public facade exposes `HydraMessage::attach_file` and `HydraAttachment::from_bytes`, not chunks/manifests. |
| `backup_history.rs` | Signed backup checkpoint history and rollback warning utilities. | Keep internal storage-hardening candidate. No public rollback/checkpoint API. |
| `chat_bootstrap.rs` | QR/join-code bootstrap payload helpers. | Reuse as contact/invite implementation candidate. Public API remains `create_contact_invite`, `add_contact`, and handshake methods. |
| `chat_shell.rs` | App chat-shell summaries and local UX model over message store. | Example/demo helper only. Do not move into public facade. |
| `contact_trust.rs` | Public contact cards, QR payloads, safety numbers, key-change warnings, encrypted contact store. | Strong facade candidate. Trim to `create_contact_card`, `add_contact`, `verify_contact`, block/unblock, import/export contacts. |
| `device_link.rs` | Multi-device approval/revocation registry. | Future internal candidate only. Not public v1 unless identity import/export requires it. |
| `error.rs` | App-domain error type. | Use as reference only. `hydra-msg` needs its own simple public error. |
| `group.rs` | App group wrappers over `hydra-group`. | Reuse later behind simple lobby API only. No checkpoint/state API. |
| `identity.rs` | App identity generation and public identity material. | Strong facade candidate. Migrate/copy behind `generate_id`, contact card, and handshake identity binding. |
| `identity_store.rs` | Encrypted identity store records, device IDs, metadata. | Strong internal candidate behind identity persistence/import/export. |
| `identity_vault.rs` | Vault, memory-only unlock sessions, active identity selection. | Strong internal candidate. Public API stays `set_active_id`, `unlock_id`, `lock_id`. |
| `live_state.rs` | Persisted live session/group state. | Internal persistence candidate. Do not expose. |
| `message_store.rs` | Stored conversations, messages, replay cursors, members. | Internal candidate for message history methods. Public API exposes only list/get/delete/clear/export/import messages. |
| `random.rs` | Random byte helpers. | Internal utility candidate if not already covered by `hydra-crypto`. |
| `recovery.rs` | Encrypted recovery backup import/export and inspection. | Internal candidate behind `export_backup`, `import_backup`, `verify_backup`. |
| `secret_handling.rs` | Storage KDF, crash-safe writes, optional keychain abstraction. | Strong internal candidate for storage safety. No public config/profile API. |
| `session.rs` | App session wrapper over `hydra-session`, handshake export material, rekey notice. | Strong facade candidate for `send`, `receive`, `rekey_session`, `close_session`. Hide `SessionHandshakeExport`. |
| `storage_recovery.rs` | App-level storage/recovery orchestration. | Internal candidate for storage status and backup/restore. Public API only gets `storage_status`. |
| `transport.rs` | In-memory transport, mailbox/upload demo types, transport rate limiter. | Example/carrier helper only. Do not put in public `hydra-msg`. |

### `examples/hydra-app`

| Area | Current role | Facade decision |
|---|---|---|
| `cli/` | Demo CLI command parser/output for local demo app. | Keep as example until replaced by future `hydra-msg-cli`/`cargo-hydra-msg`. |
| `config.rs` | App/demo runtime config and data-dir defaults. | Do not move into public facade. Public API has `Hydra::open(data_dir)` only. |
| `contacts.rs` | CLI/GUI contact-book adapter over app-core trust store. | Reuse behavior ideas only; facade owns its own contact methods. |
| `gui/` | Local browser GUI routing/security/assets/state. | Example only. No protocol authority. |
| `secrets.rs` | Demo app storage-secret loading. | Reuse crash-safe/local-secret ideas internally only if needed. No public config/profile API. |
| `services/` | Shared CLI/GUI orchestration over app-core. | Example only. Do not move into facade. |

## Public API coverage map

| Public API group | Existing code to reuse | Gaps before facade crate |
|---|---|---|
| `Hydra::open`, `open_default`, `data_dir` | `examples/hydra-app/src/config.rs`, `secret_handling.rs` | Need new facade-owned storage root and defaults without `HydraConfig` or profiles. |
| Identity | `identity.rs`, `identity_store.rs`, `identity_vault.rs`, `recovery.rs` | Need simple ID type, import/export bytes format, and facade-owned error mapping. |
| Contacts | `contact_trust.rs`, `contacts.rs`, `chat_bootstrap.rs` | Need contact card type, contact ID type, safety-code verification path, block/unblock storage. |
| Handshake/session setup | `session.rs`, lower `hydra-session` | Need real offer/answer types and handshake layer binding to identity/contact material. |
| Messaging | `session.rs`, `message_store.rs` | Need `HydraMessage` packing and `ReceivedHydraMessage` accessors. |
| Attachments as payload convenience | `attachment.rs` | Need internal pack/chunk/reassemble hidden behind `HydraMessage::attach_file` and `HydraAttachment::from_bytes`. |
| Message history | `message_store.rs` | Need import/export methods and clear public semantics for stored vs received messages. |
| Groups/lobbies | `group.rs`, `hydra-group` | Need trimmed lobby API only; no checkpoint/state/predicate methods. |
| Backup/restore | `recovery.rs`, `storage_recovery.rs`, `backup_history.rs` | Need simple `export_backup`, `import_backup`, `verify_backup` without exposing options in v1. |
| Diagnostics | `storage_recovery.rs`, benchmark example code | Need `storage_status` and `benchmark` only. |

## Duplicate or confusing abstractions to avoid

- Do not expose `HydraConfig`, `HydraProfile`, a builder, or advanced mode in v1.
- Do not expose `SessionHandshakeExport`, session snapshots, session import/export,
  envelope classes, route tags, chunk APIs, protocol-info APIs, or supported-suite APIs.
- Do not expose `transport.rs` mailbox/upload helpers through `hydra-msg`.
- Do not expose AOL2/Kaspa/ZK/predicate/checkpoint APIs through `hydra-msg`.
- Do not make `hydra-msg` depend on `examples/hydra-app-core`; copy or migrate only
  the required implementation into internal modules when the facade is created.

## P3 creation plan

The next implementation step is `crates/hydra-msg`.

Start with a facade crate that owns:

```text
src/lib.rs
src/error.rs
src/hydra.rs
src/identity.rs
src/contact.rs
src/handshake.rs
src/message.rs
src/storage.rs
src/backup.rs
src/diagnostics.rs
```

The first pass should expose the public type names and method signatures from
`public-developer-api.md`, then wire each method to migrated internals one group
at a time. The crate must not introduce an advanced public API while doing this.
