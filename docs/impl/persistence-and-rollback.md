# HYDRA-MSG persistence and rollback profile

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)
- [Anonymous authorization](../spec/anonymous-authorization.md)

HYDRA defines no persistence for live sessions, sender chains, skipped keys,
group traffic keys, or TreeKEM private paths.

## HYDRA-MSG facade native local state

The current `hydra-msg` facade native adapter stores normal local state as opaque authenticated-encrypted bytes in `state.hydra`. The adapter boundary is intentionally narrow:

```text
Hydra facade
  -> canonical plaintext snapshot in memory
  -> authenticated encrypted state envelope
  -> native opaque-byte file adapter
```

The native adapter does not parse identity records, messages, attachments, contacts, lobbies, anonymous-authorization state, KDF records, or decrypted snapshot records. It only reads and writes opaque bytes and a local rollback sidecar.

Native writes use a create-new temporary file, complete write, file sync, replacement, and parent-directory sync where supported. Stale temporary files are removed before a new write and are never treated as committed state. If a write fails, the facade returns an error and restores the previous in-memory `state_generation` instead of pretending the failed write committed.

The native open path distinguishes missing storage from corrupt storage. A missing `state.hydra` creates a new empty state. Wrong passwords, corrupt headers, corrupt ciphertext/tag, truncated files, malformed snapshots, and stale generations fail closed and do not fall back to plaintext, empty state, backup blobs, or legacy formats.

On Windows, the current standard-library replacement path removes an existing destination before rename because Rust's portable `std::fs::rename` API does not guarantee atomic replacement over existing files on Windows. Strict Windows atomic-replace semantics remain a future hardening item if Windows-native durability is a release blocker.


Encrypted local snapshots and backups use chunked padded storage envelopes. The canonical plaintext snapshot is packed with its exact length inside authenticated plaintext, padded with zero bytes to fixed-size encrypted chunks, and then sealed per chunk. The final chunk is always full-sized after padding; larger states automatically add more fixed-size chunks. This minimizes exact-size leakage while still honestly exposing chunk count, KDF/header metadata, file existence, and storage-provider timing.

## HYDRA-MSG facade browser state

The current `hydra-msg` browser persistence boundary stores normal browser state as opaque authenticated-encrypted snapshot bytes in IndexedDB; `hydra-msg-wasm` exposes that boundary as the JavaScript `WasmHydra` facade:

```text
WasmHydra.openPersistent(name, password)
  -> IndexedDB load from hydra-msg/snapshots[name]
  -> hydra-msg browser persistence opens authenticated encrypted state internally
  -> explicit WasmHydra.flush() after mutations
  -> hydra-msg browser persistence writes opaque encrypted state internally
```

The browser persistence boundary owns IndexedDB storage mechanics only. It does not parse HYDRA plaintext snapshots, inspect KDF fields, derive keys, read identity/contact/message/lobby records, or store plaintext state. The JavaScript record stores only opaque encrypted snapshot bytes, a compare-and-swap revision, and adapter format metadata. It must not store plaintext state, profile write timestamps, contact/message counts, or debug counters.

Browser persistence fails closed when IndexedDB is unavailable, blocked, quota-limited, cleared, or rejected by private-browsing policy. It does not fall back to plaintext, `localStorage`, or durable-looking in-memory state. `WasmHydra.openEphemeral(name, password)` is intentionally available for tests and benchmarks that do not want durable state.

Browser rollback protection is currently weaker than native rollback protection because this milestone does not add an IndexedDB sidecar rollback guard. The authenticated `state_generation` remains inside ciphertext, but a local attacker or browser restore event that replays an older IndexedDB record may not be distinguishable without external freshness evidence. Strong rollback resistance still requires peer revalidation, hardware monotonic storage, an authenticated service, or another external freshness anchor.

The `mobile_perf_web` example is the current browser validation harness. It exercises first open with empty IndexedDB state, reopen of existing state, explicit `flush()` after identity/contact/session/message/attachment mutations, backup export/verify/import, restore dirty-state checks, encrypted snapshot byte growth, page-reload reopen, browser API misuse rejection, and non-destructive quota/lifecycle probing. The harness records browser-reported storage estimates but does not intentionally exhaust quota. IndexedDB records intentionally omit durable write timestamps, and browser status APIs expose redacted status by default with explicit debug status reserved for development/testing.

## HYDRA-MSG facade backup restore semantics

Backups are explicit user-controlled portability/recovery artifacts. Normal Native/CLI and WASM persistence must continue storing encrypted local snapshots through their active adapters instead of hiding backup blobs as app state.

`verify_backup(bytes, password)` authenticates the backup ciphertext and validates the decrypted canonical snapshot without mutating local state. `import_backup(bytes, password)` is a restore/replacement operation: it authenticates, validates, applies the snapshot through the same canonical apply path, preserves the target instance's local generation floor, and then commits through the active persistence boundary.

Native restore is facade-transactional. The previous in-memory snapshot is captured before restore. If the native adapter reports a commit failure, the facade reapplies the previous snapshot before returning the error, so memory does not claim a restore that disk rejected. A native write can still fail after partial filesystem side effects; final release validation must continue treating filesystem durability claims conservatively.

WASM restore uses the explicit browser durability boundary from the public API shape phase. `importBackup(bytes, password)` marks the wrapper dirty. The restore becomes durable in IndexedDB only after `await hydra.flush()` succeeds. If `flush()` fails because IndexedDB is unavailable, quota-limited, blocked, evicted, or cleared, the app must surface the error and must not fall back to plaintext, `localStorage`, or durable-looking in-memory state.

Restored state is rollback-uncertain. A valid old backup can authenticate correctly while still representing older local truth. During restore, the target's local `state_generation` floor must not move backward. Stronger restore freshness requires external peer revalidation, hardware monotonic storage, an authenticated service, or another external freshness anchor.

## 1. Persisted public/control state

Implementations may persist:

```text
accepted device fingerprints and trust decisions
identity public metadata and protected identity-key handle
monotonic identity rotation/revocation policy versions
group ID, mode, policy, canonical roster, public tree
last accepted group commit hash, epoch, and state version
application ciphertext and delivery metadata
```

Group public/control state is authenticated but rollback-sensitive.

## 2. Never persisted

```text
handshake/refresh secrets
refresh roots
direction/group chain or message keys
skipped keys and replay candidate keys
group epoch/root secrets
TreeKEM path secrets or node decapsulation keys
AEAD/plaintext/scratch buffers
deterministic vector RNG state in production
```

## 3. Atomic public-state record

The persisted group record binds:

```text
storage_format = 1
group_id
group_mode
epoch
state_version
last_commit_hash
roster_hash
tree_hash
public_state_hash[64]
```

```text
public_state_hash = SHA3-512(
  "HYDRA-MSG/v1/storage/public-state-hash" || suite_id ||
  LP(canonical persisted public state excluding public_state_hash)
)
```

Writes use create-new temporary storage, complete write, file sync, atomic
rename, and parent-directory sync where supported. Parsing applies the same
canonical and resource bounds as network input.

## 4. Rollback detection

At least one non-rollbackable authority must bind the greatest accepted
rotation/revocation version and group `(epoch, state_version, commit_hash)`:
hardware monotonic storage, an authenticated transparency/account service, or
explicit revalidation with trusted peers. A local file alone is insufficient.

If freshness cannot be established after restart, the implementation:

1. sends no application data under restored state;
2. rejects delivery from uncertain group state;
3. performs a new authenticated 1:1 handshake;
4. obtains and validates current group public state plus a fresh welcome; and
5. resumes only after installing a fresh epoch.

## 5. Backup and restore

Backups may contain encrypted identity-key material and public/control state,
but never live traffic state. Restore is treated as rollback-uncertain and
follows Section 4. Cloning one device backup does not create two valid devices;
one clone must receive a new independently trusted device identity.

## 6. Crash semantics

A crash may lose undelivered messages and reserved send indices. It must not
cause key/nonce reuse because no live chain is restored. Pending partial
fragments and provisional commits are discarded.

## Release-readiness status

The persistence milestone is implementation-complete for the current design: Native/CLI and browser/WASM both use the same core canonical snapshot semantics, platform adapters store opaque encrypted bytes, backups authenticate and validate with a password before verify/import succeeds, and QA guardrails reject stale passwordless backup verification, `localStorage` state use, durable-looking no-op WASM open aliases, duplicate snapshot parsers, and plaintext state-format resurrection.

The implementation should still be described conservatively. Native file replacement is hardened but inherits platform filesystem semantics, especially around Windows replacement behavior and power-loss windows. Browser IndexedDB durability is subject to browser quota, eviction, private-browsing policy, blocked database upgrades, user-cleared site data, and mobile lifecycle behavior. Backup restore authenticates bytes but cannot prove that the backup is the newest possible state without external freshness evidence.

Before a release claim, run the full master validation path on a machine with Rust, wasm-pack tooling, Node, and a real browser. Capture fresh desktop and mobile browser results from `examples/mobile_perf_web` and record them in [Benchmark notes](../validation/benchmark-results.md).
