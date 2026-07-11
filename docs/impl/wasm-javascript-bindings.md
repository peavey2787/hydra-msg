# HYDRA-MSG WASM / JavaScript Bindings

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](message-flow/README.md)
- [Spec docs and repo structure](../spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../spec/public-developer-api.md)
- [Benchmark notes](../validation/benchmark-results.md)

Status: browser/mobile binding implementation notes.

Goal: make the same simple HYDRA API usable from browser/mobile apps without exposing crypto/session/wire internals.

## Rules

- No `HydraConfig`, profiles, builders, or advanced public API.
- No protocol-info, supported-suite, session export/import, checkpoint, predicate, or lobby-state APIs.
- Transport sizing is exposed only as `setPacketSize(bytes)` and `packetSize()`; apps do not see chunk controls. `send()` returns one or more opaque packets and `receive()` returns `null` until a full message has been reassembled.
- WebRTC, relays, HTTP, QR codes, files, Kaspa pointers, and libp2p remain carriers only.
- Browser apps send opaque HYDRA bytes over whatever carrier they choose.
- Browser persistence uses IndexedDB for opaque authenticated-encrypted chunked state bytes.
- JavaScript must not parse HYDRA plaintext snapshots, KDF records, identity records, contacts, messages, lobbies, or attachments.
- `localStorage` must not be used for HYDRA state. It is only acceptable for non-secret UX preferences if a future app needs them.

## Crate

```text
crates/hydra-msg-wasm
```

The crate wraps `hydra-msg` and exposes JS-friendly method names.

## Persistent IndexedDB open

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = await WasmHydra.openPersistent('default-profile', 'state-password');
const id = hydra.generateId('password');
hydra.setActiveId(id, 'password');
await hydra.flush();

const myCard = hydra.createContactCard();
const preview = JSON.parse(hydra.previewContactCard(myCard));
const contactId = hydra.addContact(myCard);
const safetyCode = hydra.contactSafetyCode(contactId);
hydra.verifyContact(contactId, safetyCode);
await hydra.flush();

const offer = hydra.initHandshake(contactId);
const answer = hydra.replyHandshake(offer);
hydra.finishHandshake(answer);
await hydra.flush();

hydra.setPacketSize(56 * 1024);
console.log(hydra.packetSize());
const packets = hydra.send(
  contactId,
  WasmHydraMessage.text('hello')
    .attachBytes('data.bin', new Uint8Array([1, 2, 3]))
);
await hydra.flush();

let data = null;
for (const packet of packets) {
  appSendToPeer(packet);
  data = hydra.receive(packet) || data;
}
await hydra.flush();
if (data) {
  console.log(data.text());
  for (let i = 0; i < data.attachmentCount(); i += 1) {
    console.log(data.attachmentFilename(i), data.attachmentBytes(i));
  }
}
```

`openPersistent(name, password)` opens the IndexedDB database named `hydra-msg`, uses the `snapshots` object store, and stores one encrypted chunked state record under the provided profile name. The adapter stores opaque encrypted bytes plus non-secret adapter metadata: adapter version and a monotonic profile revision. It does not store a production write timestamp.

`flush()` is explicit because IndexedDB is async. After mutating calls, the wrapper marks itself dirty and `flush()` writes the newest encrypted chunked state container. This is the final WASM API shape for this milestone: mutating calls stay synchronous, and apps commit durable browser state by awaiting `flush()` at clear transaction boundaries.

`flush()` is not a blind put. It performs a single IndexedDB `readwrite` transaction that reads the current profile revision and writes only if it still matches the revision loaded by this wrapper. This compare-and-swap rule prevents last-writer-wins corruption when two browser tabs, workers, or mobile page instances open the same profile. A stale writer receives a storage error, remains dirty, and must reopen or ask the user to resolve the conflict before trying to commit again.

## Ephemeral open

```javascript
const hydra = WasmHydra.openEphemeral('benchmark-profile', 'state-password');
```

Ephemeral mode is for tests, examples, and benchmarks that intentionally do not need durable state. The WASM binding intentionally exposes no ambiguous `open()` or `openDefault()` aliases. Browser apps that need persistence must use `await WasmHydra.openPersistent(...)`.

The binding also exposes password rotation helpers:

```javascript
hydra.changeStatePassword('old-state-password', 'new-state-password');
hydra.changeIdPassword(identityIdHex, 'old-id-password', 'new-id-password');
await hydra.flush();
```


## Backup restore in browser apps

```javascript
const backup = hydra.exportBackup('backup-password');
hydra.verifyBackup(backup, 'backup-password');

const restored = await WasmHydra.openPersistent('restored-profile', 'state-password');
restored.importBackup(backup, 'backup-password');
await restored.flush();
```

`verifyBackup(bytes, password)` authenticates the backup and validates the decrypted snapshot without mutating the wrapper. `importBackup(bytes, password)` applies a verified restore snapshot through the same core snapshot path as Native/CLI and marks the wrapper dirty. It is not durable in IndexedDB until `flush()` succeeds. Apps should surface `flush()` errors and keep encrypted backups available for user-controlled recovery.

## Delete persistent state

```javascript
await WasmHydra.deletePersistent('default-profile');
```

This deletes the IndexedDB snapshot record for that profile name. It does not delete user-exported backups.

## Browser lifecycle and failure behavior

The adapter fails closed if IndexedDB is unavailable, blocked by another tab, quota-limited, denied by private-browsing policy, stale by profile-revision comparison, or cleared by the user/browser. It does not fall back to plaintext, `localStorage`, or durable-looking in-memory state.

Private browsing, storage eviction, mobile background kills, and browser persistent-storage denial can make IndexedDB unavailable or non-permanent. Apps should surface those errors and encourage users to keep encrypted backups for portability and recovery. HYDRA exposes two small helpers for app diagnostics:

```javascript
const status = JSON.parse(await WasmHydra.browserLifecycleStatus());
const persistentStorageGranted = await WasmHydra.requestPersistentStorage();
```

`browserLifecycleStatus()` reports IndexedDB availability, quota estimate availability, and whether the browser says persistent storage has already been granted. `requestPersistentStorage()` calls `navigator.storage.persist()` when available and returns `false` when the browser denies or lacks that API. Denial is not fatal by itself, but the app must treat the profile as eviction-prone.

Recommended app behavior:

```text
openPersistent failure -> show a storage-unavailable error and do not silently continue as durable
flush stale-profile    -> stop writes, keep local changes marked unsaved, reopen before committing
flush quota failure    -> ask the user to export an encrypted backup and reduce local data
persistent denied      -> warn that browser state can be evicted and encourage backups
user-cleared storage   -> treat as a fresh device unless the user imports an encrypted backup
private browsing       -> warn that durable persistence may be unavailable or short-lived
mobile background kill -> flush before backgrounding and still rely on explicit backups
```

Versioned DB format uses IndexedDB version `2`. HYDRA is still pre-v1, so this first production candidate does not preserve old browser records, old write timestamps, or old revisionless formats; incompatible records fail closed rather than migrating silently.

The public JS boundary intentionally remains small: `openPersistent`, `openEphemeral`, `flush`, `deletePersistent`, browser lifecycle status/persistence request, backup export/import/verify, and the messaging/contact/lobby facade methods, including contact/lobby preview helpers and one-time contact/lobby invite helpers. IndexedDB names, object-store mechanics, encrypted chunked state bytes, KDF fields, and rollback internals are not normal app APIs.

## Build

The source of truth is always:

```text
crates/hydra-msg-wasm
```

Build the reusable web package from the repo root:

```bash
./qa/ci/core/build-wasm-web.sh
```

PowerShell:

```powershell
.\qa\ci\core\build-wasm-web.ps1
```

The reusable package is written to:

```text
target/hydra-msg-wasm/web/
```

Example hosts build their own `web/pkg/` output only when testing examples:

```bash
examples/mobile_perf_web/scripts/build-wasm.sh
cargo run --release --manifest-path examples/mobile_perf_web/Cargo.toml -- 0.0.0.0:8788
```

Open the LAN URL from a phone/tablet/browser and use the benchmark page to run:

- the browser/device ephemeral WASM facade benchmark;
- the IndexedDB persistence validation suite;
- the reopen-after-page-reload check;
- the API misuse guard for missing names/passwords and empty profile names;
- the multi-tab stale-writer probe that proves revision compare-and-swap rejects last-writer-wins;
- the crash-consistency probe for aborted IndexedDB transactions;
- the non-destructive quota/lifecycle probe.

The persistence validation suite records first-open, reopen, flush-after-mutation, backup export/import, message/attachment growth, encrypted snapshot byte length, and browser storage estimates. It is a validation harness, not a claim that browser storage cannot be evicted.

## Metadata-minimized lobby routing and storage status

Lobby copies expose `routingHint()` and `routingHintHex()` for mailbox or relay routing. `recipient()` remains available only for direct/local routing and is not privacy-preserving. Prefer routing hints or mailbox aliases when the carrier can route opaque envelopes without stable contact identifiers.

`storageStatus()` is redacted for production surfaces and omits identity/contact/lobby/message counts and state generation. `storageDebugStatus()` is explicitly diagnostic and must not be logged or exposed in production telemetry.
