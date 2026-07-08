# hydra-msg-wasm

`hydra-msg-wasm` provides browser/mobile bindings over the `hydra-msg` Rust SDK.

## Navigation

- [Main README](../../README.md)
- [Crates](../README.md)
- [How HYDRA messaging works](../../docs/project/message-flow/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../../docs/project/public-developer-api.md)

## Build reusable browser package

From the repo root:

```bash
./qa/ci/build-wasm-web.sh
```

PowerShell:

```powershell
.\qa\ci\build-wasm-web.ps1
```

Output:

```text
target/hydra-msg-wasm/web/
```

Example browser hosts build their own `web/pkg/` folders only when testing those examples.

## Minimal browser shape

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = WasmHydra.openDefault();
const id = hydra.generateId('password');
hydra.setActiveId(id, 'password');

const contactId = hydra.addContact(peerContactCardBytes);
const offer = hydra.initHandshake(contactId);
appSendToPeer(offer);
const answer = await appWaitForPeerAnswer();
hydra.finishHandshake(answer);

const envelope = hydra.send(contactId, WasmHydraMessage.text('hello'));
appSendToPeer(envelope);
```

## Public surface rule

The binding mirrors the small public SDK shape. It does not expose protocol internals, configs, profiles, builders, suite selection, session import/export, public chunking, checkpoint APIs, predicate APIs, or lobby-state APIs.

Browser persistence is in-memory unless the app uses backup/import/export helpers.
