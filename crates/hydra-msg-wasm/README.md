# hydra-msg-wasm

`hydra-msg-wasm` provides browser/mobile bindings over the `hydra-msg` Rust SDK.

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)

## Build reusable browser package

From the repo root:

```bash
./qa/ci/core/build-wasm-web.sh
```

PowerShell:

```powershell
.\qa\ci\core\build-wasm-web.ps1
```

Output:

```text
target/hydra-msg-wasm/web/
```

Example browser hosts build their own `web/pkg/` folders only when testing those examples.

## Minimal persistent browser shape

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = await WasmHydra.openPersistent('default-profile', 'state-password');
const id = hydra.generateId('password');
hydra.setActiveId(id, 'password');
await hydra.flush();

const contactId = hydra.addContact(peerContactCardBytes);
const offer = hydra.initHandshake(contactId);
await hydra.flush();
appSendToPeer(offer);

const answer = await appWaitForPeerAnswer();
hydra.finishHandshake(answer);
await hydra.flush();

// For carriers with small per-message limits, configure one packet ceiling.
// 56 KiB maps to HYDRA Standard-size packets internally.
hydra.setPacketSize(56 * 1024);
console.log(hydra.packetSize());
const packets = hydra.send(contactId, WasmHydraMessage.text('hello'));
await hydra.flush();
for (const packet of packets) {
  appSendToPeer(packet);
}
```

`openPersistent(name, password)` loads and saves opaque authenticated-encrypted HYDRA chunked state containers in IndexedDB. The JavaScript adapter does not parse identities, contacts, messages, lobbies, attachments, KDF records, or plaintext state records.

`flush()` is the final durable-write boundary for the WASM API. Mutating methods update in-memory HYDRA state synchronously and mark the wrapper dirty; browser apps must call `await hydra.flush()` at transaction boundaries to commit the newest encrypted chunked state container to IndexedDB. This avoids converting every mutating method into an async IndexedDB write and keeps batch updates efficient.

The IndexedDB adapter stores a non-secret profile revision next to the opaque encrypted chunked state container. `flush()` performs a transactional compare-and-swap against the revision observed by `openPersistent()`. If another tab, worker, or page instance already committed the same profile, the stale flush fails closed instead of overwriting newer state. The stale wrapper remains dirty and the app must reopen the profile, export a backup, or ask the user how to resolve the conflict.

Browser lifecycle helpers are intentionally small:

```javascript
const status = JSON.parse(await WasmHydra.browserLifecycleStatus());
const granted = await WasmHydra.requestPersistentStorage();
```

`browserLifecycleStatus()` reports IndexedDB and storage-persistence availability without exposing encrypted state bytes. `requestPersistentStorage()` asks the browser for best-effort persistent storage when supported; denial means state remains eviction-prone and apps should warn users to keep encrypted backups.

## Backup restore boundary

```javascript
const backup = hydra.exportBackup('backup-password');
hydra.verifyBackup(backup, 'backup-password');

const restored = await WasmHydra.openPersistent('restored-profile', 'state-password');
restored.importBackup(backup, 'backup-password');
await restored.flush();
```

`verifyBackup(bytes, password)` authenticates the backup and validates the decrypted snapshot without mutating the wrapper. `importBackup(bytes, password)` is a restore/replacement operation and marks the persistent wrapper dirty. The restored state is durable in IndexedDB only after `flush()` succeeds.

## Ephemeral browser shape

```javascript
const hydra = WasmHydra.openEphemeral('benchmark-profile', 'state-password');
```

Use ephemeral mode only for tests, examples, and benchmarks that intentionally do not need durable state. The WASM binding intentionally exposes no ambiguous `open()` or `openDefault()` aliases, so browser apps must choose either `await WasmHydra.openPersistent(...)` for durable state or `WasmHydra.openEphemeral(...)` for explicit in-memory state.

## Reset persistent browser state

```javascript
await WasmHydra.deletePersistent('default-profile');
```

Deleting a persistent profile removes the IndexedDB record for that profile name. It does not affect backups the user exported separately.

## Browser persistence validation

Use `examples/mobile_perf_web` to validate browser/mobile persistence behavior. The page includes an IndexedDB persistence suite, a reopen-after-page-reload check, a multi-tab stale-writer probe, a browser API misuse guard for missing names/passwords, a crash-consistency probe, and a non-destructive quota/lifecycle probe. Results should be recorded in [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md) before claiming browser persistence is release-final.

## Public surface rule

The binding mirrors the small public SDK shape. It does not expose protocol internals, profiles, builders, suite selection, session import/export, checkpoint APIs, predicate APIs, lobby-state APIs, or chunk controls. The only transport sizing control is `setPacketSize(bytes)`, with `packetSize()` as the getter. `send()` returns one or more opaque packets, and `receive()` returns `null` until a full message has been reassembled. Password rotation is exposed through `changeStatePassword(...)` and `changeIdPassword(...)`; preview helpers are exposed through `previewContactCard(...)` and `previewLobbyInvite(...)`.

## WASM stack size

HYDRA-MSG's browser handshake path performs ML-KEM and ML-DSA work. The example and CI WASM build scripts set an explicit 16 MiB wasm-ld stack:

```bash
HYDRA_WASM_STACK_SIZE=16777216 examples/mobile_perf_web/scripts/build-wasm.sh
```

Apps embedding the package should keep an explicit stack size and rerun the browser benchmark plus IndexedDB persistence suite after changing it.
