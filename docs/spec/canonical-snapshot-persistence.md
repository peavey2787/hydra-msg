# Canonical encrypted local snapshot persistence

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

This document defines the current encrypted local-state and backup persistence contract used by the `hydra-msg` facade. It is an internal storage format, not a public app-facing export format. App-controlled portability uses the encrypted backup API.

## Ownership boundary

| Layer | Owner | Responsibility |
|---|---|---|
| Facade orchestration | `crates/hydra-msg/src/api/storage.rs` | Opens HYDRA, imports/exports backups, verifies backups, reports storage status, and delegates persistence. |
| Plaintext snapshot model | `crates/hydra-msg/src/persistence/snapshot.rs` | Builds, validates, and applies the current internal state snapshot. |
| Storage codec | `crates/hydra-msg/src/codec/storage.rs` | Seals, opens, chunks, pads, and validates encrypted state/backup containers. |
| KDF record | `crates/hydra-msg/src/codec/kdf.rs` | Owns password KDF names, profiles, parameters, salts, validation, and key derivation. |
| Native adapter | `crates/hydra-msg/src/persistence/native_store.rs` | Reads, writes, locks, deletes, and lists opaque encrypted bytes using native file semantics. |
| Browser adapter | `crates/hydra-msg/src/browser/persistence.rs` | Reads, writes, deletes, and lists opaque encrypted bytes using IndexedDB compare-and-swap revisions. |
| Rollback guard | `crates/hydra-msg/src/persistence/rollback.rs` | Records local native freshness evidence and rejects locally stale generations where possible. |

Adapters own durability mechanics only. They must not parse or mutate plaintext HYDRA state.

## Current-version-only rule

HYDRA-MSG is pre-v1 and has one current local persistence format. Unsupported magic, malformed KDF fields, malformed nonce, malformed ciphertext, invalid UTF-8, unsupported record kinds, duplicate scalar records, duplicate collection records, and unknown future versions fail closed.

A missing state record is distinct from a corrupt state record. Missing storage may create a new empty profile. Corrupt or unauthenticated storage must return an error and must not silently fall back to plaintext, legacy state, `localStorage`, or durable-looking memory state.

## Plaintext snapshot model

The authenticated plaintext snapshot is UTF-8 text with tab-separated records and lowercase contiguous hex for binary fields:

```text
HYDRA-MSG-STATE-SNAPSHOT\n
state_generation\t<decimal u64>\n
next_message_id\t<decimal u64>\n
anonymous_auth_secret\t<hex secret>\n
anonymous_auth_spent\t<hex nullifier>\n
identity\t...\n
contact\t...\n
message\t...\n
lobby\t...\n
```

The authoritative local generation is the `state_generation` field inside authenticated ciphertext. The production storage-status API redacts counts and generations; debug status is a separate explicit debug API.

Runtime-only values such as pending handshake offers and unlocked identity seeds are not persisted as plaintext snapshot fields.

## Encrypted local snapshot envelope

The current native encrypted-state magic is:

```text
HYDRA-MSG-STATE
```

The current backup magic is:

```text
HYDRA-MSG-BACKUP
```

Both state and backup containers use fixed-size authenticated encrypted chunks:

```text
<magic>
kdf\tscrypt
kdf_profile\t<profile>
kdf_log_n\t<decimal>
kdf_r\t<decimal>
kdf_p\t<decimal>
kdf_salt\t<64 lowercase hex chars>
format_version\t1
chunk_size\t65536
chunk_count\t<decimal>
nonce\t<24 lowercase hex chars>
chunk\t0\t<lowercase hex ciphertext>
chunk\t1\t<lowercase hex ciphertext>
...
```

Before encryption, the snapshot is packed as:

```text
HYDRA-MSG-STORAGE-PLAINTEXT\n
<u64 snapshot length><snapshot bytes><zero padding to chunk_size>
```

Every chunk is encrypted separately. The envelope header through the `nonce` line is authenticated as associated data, and each chunk also authenticates its chunk index. The final chunk is padded to the full fixed chunk size. Large valid snapshots add more chunks; HYDRA does not expose a short final chunk.

State and backup are cryptographically separated by different magic values and different key-derivation labels:

```text
HYDRA-MSG/facade/state-key
HYDRA-MSG/facade/backup-key
```

A valid backup chunk pasted into state, a valid state chunk pasted into backup, valid chunks under the wrong AAD, wrong chunk indexes, wrong chunk count, wrong final padding, and mixed chunks from another backup must all fail authentication or validation.

## KDF profiles

The current KDF is `scrypt` with validated profiles:

| Profile | log_n | r | p |
|---|---:|---:|---:|
| `mobile` | 13 | 8 | 1 |
| `interactive` | 14 | 8 | 1 |
| `high-security` | 15 | 8 | 1 |

The salt is 32 random bytes and must not be all zeroes. Empty passwords are invalid. Password input is capped before KDF work.

## Current facade resource ceilings

`crates/hydra-msg/src/limits.rs` is the source of truth for facade resource ceilings. The current values are:

| Boundary | Current ceiling |
|---|---:|
| Encrypted local-state container | `MAX_STATE_SNAPSHOT_BYTES * 2 + 512 KiB` |
| Encrypted backup container | `MAX_STATE_SNAPSHOT_BYTES * 2 + 512 KiB` |
| Authenticated plaintext snapshot | 64 MiB |
| Storage chunk plaintext size | 65,536 bytes |
| Identities | 256 |
| Contacts | 1,024 |
| Lobbies | 256 |
| Stored messages | 100,000 total |
| Stored messages per contact | 10,000 |
| Spent anonymous-auth nullifiers | 100,000 |
| Contact card bytes | 16 KiB |
| Contacts import bytes | 16 MiB |
| Imported contact records | 1,024 |
| Message import bytes | 64 MiB |
| Lobby invite bytes | 64 KiB |
| Anonymous-auth token bytes | 4 KiB |
| Identity export bytes | 1 KiB |
| Password bytes | 1 KiB |
| Label bytes | 256 |
| Attachment filename bytes | 255 |
| Message plaintext bytes | 4 MiB |
| Attachments per message | 16 |
| Attachment bytes | 16 MiB |
| Encoded message payload | 32 MiB |
| Fragmented logical payload | `MAX_PACKED_MESSAGE_BYTES + 64 KiB` |
| Stored message bytes | 256 MiB total; 64 MiB/contact |
| Lobby outbound packets | 4,096 |
| Lobby outbound envelope bytes | 64 MiB |
| Handshake offer bytes | 16 KiB |
| Handshake answer bytes | 16 KiB |
| Pending handshakes | 64 |
| Pending handshake age | 10 minutes |
| Fragment parts retained globally | 16,384 |
| Fragments per logical message | 16,384 |
| Incomplete fragmented messages | 128 global; 8/contact; 8/lobby |
| Pending fragment bytes | 64 MiB |
| Fragment age | 10 minutes |

Inputs over these ceilings fail before allocation-heavy parsing, cryptography, or state mutation whenever the public API can enforce that ordering.

## Native durability and rollback behavior

Native persistence writes through a temporary file, syncs the temporary file, renames/replaces the state file, syncs the parent directory where supported, and records rollback evidence in a sidecar guard file. A same-profile native lock prevents two live `Hydra::open()` handles from using the same data directory concurrently.

Crash-consistency tests prove that interrupted writes leave either the previous authenticated state or the new authenticated state openable, and that destructive operations revert in-memory state when persistence fails.

## Browser IndexedDB behavior

The browser adapter stores one opaque encrypted state container per profile in IndexedDB. It does not store HYDRA state in `localStorage`, parse ciphertext in JavaScript, or persist plaintext objects.

Browser records include non-secret adapter metadata, including an explicit adapter version and a monotonic profile revision used for compare-and-swap writes. `openPersistent()` records the loaded revision. `flush()` succeeds only if the durable record still has that revision. Stale tabs, workers, or pages fail closed instead of using last-writer-wins semantics.

The adapter exposes unavailable IndexedDB, blocked opens, private-browsing-style failures, quota exhaustion, stale revisions, user-cleared storage, and eviction as explicit errors. Apps should flush before backgrounding and keep encrypted backup recovery visible.

## Backup relationship

Backups and local state share the snapshot validation path after decryption, but they are not interchangeable containers. Backup verification authenticates and validates without mutation. Backup import is a replacement operation. Native import is failure-atomic in memory and on disk. WASM import marks the wrapper dirty and becomes durable only after `flush()` succeeds.

A restored snapshot must not lower the target instance's local generation floor. After restore, the next persisted generation is promoted to at least the target's prior generation.

## Vector and adversarial requirements

Persistence vectors and tests must include:

```text
current encrypted state positive vectors
current encrypted backup positive vectors
wrong password/corruption/truncation cases
unknown future format cases
missing, duplicate, reordered, extra, wrong-size, and wrong-index chunks
wrong final padding and wrong snapshot length inside padded plaintext
valid chunks under wrong AAD
state/backup chunk cross-paste cases
mixed chunks from another backup
stale generation and rollback-floor cases
```

The current fixture and interop requirements live under `qa/fixtures/interop/`, `qa/vectors/`, `qa/evidence/`, and `docs/validation/test-vectors.md`.
