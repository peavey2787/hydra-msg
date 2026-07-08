# hydra-msg-wasm

WASM/JavaScript bindings over the stupid-simple `hydra-msg` facade.

This crate mirrors the public Rust SDK shape and does **not** expose protocol internals, configs, profiles, builders, suite selection, session export/import, public chunking, checkpoint APIs, predicate APIs, or lobby-state APIs.

Build from the repo root:

```bash
wasm-pack build crates/hydra-msg-wasm --target web --release --out-dir ../../examples/mobile_perf_web/web/pkg
```

Minimal browser shape:

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = WasmHydra.openDefault();
const id = hydra.generateId('password');
hydra.setActiveId(id, 'password');

const card = hydra.createContactCard();
const contactId = hydra.addContact(card);
const safetyCode = hydra.contactSafetyCode(contactId);
hydra.verifyContact(contactId, safetyCode);

const offer = hydra.initHandshake(contactId);
const answer = hydra.replyHandshake(offer);
hydra.finishHandshake(answer);

const envelope = hydra.send(
  contactId,
  WasmHydraMessage.text('hello').attachBytes('data.bin', new Uint8Array([1, 2, 3]))
);
const data = hydra.receive(envelope);
console.log(data.text());
```

Browser persistence in this phase is in-memory unless the app explicitly uses `exportBackup` / `importBackup` or individual export/import helpers.
