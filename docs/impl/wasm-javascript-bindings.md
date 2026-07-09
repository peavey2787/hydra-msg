# HYDRA-MSG WASM / JavaScript Bindings

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](message-flow/README.md)
- [Spec docs and repo structure](../spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../spec/public-developer-api.md)
- [Benchmark notes](../validation/benchmark-results.md)

Status: P6 binding target and implementation notes.

Goal: make the same simple HYDRA API usable from browser/mobile apps without exposing crypto/session/wire internals.

## Rules

- No `HydraConfig`, profiles, builders, or advanced public API.
- No protocol-info, supported-suite, session export/import, public chunking, checkpoint, predicate, or lobby-state APIs.
- WebRTC, relays, HTTP, QR codes, files, Kaspa pointers, and libp2p remain carriers only.
- Browser apps send opaque HYDRA bytes over whatever carrier they choose.
- Browser persistence in P6 is in-memory unless the app explicitly calls backup/import/export helpers.

## Crate

```text
crates/hydra-msg-wasm
```

The crate wraps `hydra-msg` and exposes JS-friendly method names:

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = WasmHydra.openDefault();
const id = hydra.generateId('password');
hydra.setActiveId(id, 'password');

const myCard = hydra.createContactCard();
const contactId = hydra.addContact(myCard);
const safetyCode = hydra.contactSafetyCode(contactId);
hydra.verifyContact(contactId, safetyCode);

const offer = hydra.initHandshake(contactId);
const answer = hydra.replyHandshake(offer);
hydra.finishHandshake(answer);

const envelope = hydra.send(
  contactId,
  WasmHydraMessage.text('hello')
    .attachBytes('data.bin', new Uint8Array([1, 2, 3]))
);

const data = hydra.receive(envelope);
console.log(data.text());
for (let i = 0; i < data.attachmentCount(); i += 1) {
  console.log(data.attachmentFilename(i), data.attachmentBytes(i));
}
```

## Build

The source of truth is always:

```text
crates/hydra-msg-wasm
```

Build the reusable web package from the repo root:

```bash
./qa/ci/build-wasm-web.sh
```

PowerShell:

```powershell
.\qa\ci\build-wasm-web.ps1
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

Open the LAN URL from a phone/tablet/browser and click **Run browser/device HYDRA WASM benchmark**.

## Storage note

Native `hydra-msg` uses filesystem persistence under the chosen data directory. Browser WASM cannot use the native filesystem path directly, so P6 opens HYDRA in memory and relies on explicit export/import helpers:

```javascript
const backup = hydra.exportBackup('backup-password');
hydra.importBackup(backup, 'backup-password');
```

A future browser app can layer IndexedDB/localStorage persistence above this without changing HYDRA protocol semantics.
