# HYDRA Chat GUI showcase

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)

`hydra-gui` is the full browser-first HYDRA capability showcase. It is deliberately designed like a normal chat application instead of an SDK route console: the default screen is conversations, messages, attachments, and automatic local-peer connection. Power-user controls stay behind **Details**, **Advanced**, and **Settings & tools**.

The example is intended to be polished and reliable enough to demonstrate the SDK. It is **not** a production network service or a hardened discovery/relay design. The LAN host deliberately auto-exchanges and auto-verifies contact cards to remove ceremony from a two-browser demonstration.
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)

## What it demonstrates

The simple path covers:

- automatic browser identity creation and encrypted IndexedDB state;
- LAN peer discovery through the local Rust host;
- automatic contact-card exchange and demo verification;
- authenticated HYDRA handshake establishment;
- direct encrypted text chat and file attachments;
- multi-peer HYDRA lobbies/groups;
- fixed-size padded packet delivery;
- the four steganographic text profiles in both direct and text-only group conversations, with AI model controls shown only when required;
- visible incoming/outgoing message colors and alignment, carrier-first stego rendering, per-message reveal, a global stego-view toggle, and a local privacy mask for the composer and message history;
- local message removal plus consent-based removal requests where every participant independently chooses whether to delete or keep a message.

Advanced panels expose the rest of the public feature set without crowding the chat screen:

- safety codes, verify/unverify, block/unblock, rename, and contact removal;
- ratchet-only or periodic fresh authenticated hybrid sessions, plus manual refresh/close;
- 4 KiB, 32 KiB, and 144 KiB packet ceilings;
- `stego-instant`, `stego-unicode`, `stego hybrid`, and `stego-ai` text carriers;
- multiple identities: create, switch, lock/unlock, rename, change password, export/import, delete;
- default, labeled, invite, and one-time contact cards;
- lobby creation, membership changes, minimal/labeled/member-list/one-time invites, join/leave/close;
- encrypted backup export, verify, restore, and encrypted-state password rotation;
- persistent IndexedDB vs explicit session-only state, saved-profile reset, persistence request, storage/lifecycle status, and debug status;
- message-history export/import/clear;
- anonymous one-time authorization token issue, nullifier, accept-once, and revoke;
- local benchmark diagnostics.

Every major capability has a small `?` control explaining what it does and where its security boundary sits.

## Architecture

Each browser owns its own `WasmHydra` identity/contact/session/message/lobby state. The native example host does **not** own browser identities, sessions, plaintext chat messages, or lobby state. It:

1. serves the static application and generated `hydra-msg-wasm` package;
2. acts as a small LAN rendezvous/opaque-message relay for the demonstration;
3. optionally runs the shared local `hydra-stego` AI model used by AI-backed cover profiles;
4. owns a separate demo-only `hydra-msg` anonymous-authorization issuer so that capability is usable from the browser showcase.

LAN relay payloads are opaque base64 blobs. HYDRA performs contact management, handshakes, encryption, ratchets, replay checks, attachments, and lobby work in each browser. Anonymous-authorization operations use the real Rust HYDRA API on the local demo host; they are intentionally independent of chat identities.

## Build the browser package

The generated `web/pkg/` output is intentionally not source-controlled. Any change to the Rust/WASM protocol facade—including the INIT/RESP/FINISH ABI—requires rebuilding it before starting the browser app. Source release archives do not ship an older generated package as if it were compatible.

Unix:

```bash
./examples/hydra-gui/scripts/build-wasm.sh
```

PowerShell:

```powershell
.\examples\hydra-gui\scripts\build-wasm.ps1
```

## Run

Local browser only:

```bash
cargo run --manifest-path examples/hydra-gui/Cargo.toml
```

Then open `http://127.0.0.1:8787` in two tabs, windows, or browser profiles. Each tab gets an independent demo profile so same-origin peers do not contend for one IndexedDB writer.

For phones or another computer on the same LAN:

```bash
cargo run --manifest-path examples/hydra-gui/Cargo.toml -- 0.0.0.0:8787
```

Open `http://<host-lan-ip>:8787` on each device. Peers should appear automatically and establish HYDRA sessions without copying contact cards or handshake blobs. INIT/RESP uses response timeouts and bounded backoff retries. FINISH is retransmitted idempotently until the responder acknowledges installation; if that acknowledgement never arrives, the initiator closes its local candidate session and starts a fresh handshake. A dropped demo-relay handshake record therefore does not leave one browser permanently stuck in a half-established state.

## Desktop icon and app-window launchers

HYDRA ships the same supplied three-headed lock artwork as browser favicons/PWA icons, as an embedded Windows executable resource, and as a Linux desktop icon. A normal browser tab still belongs to the browser application and the operating system may group it under the browser icon. For a dedicated HYDRA app window/taskbar identity, use the provided app launchers.

Windows uses `.cmd`-only user-facing launchers. From the repository root, double-click `scripts\install-hydra-windows.cmd` once, or just double-click `scripts\run-hydra-windows.cmd`; the launcher self-registers the per-user command shims. No administrator rights or permanent PowerShell execution-policy change is required. After registration, launch from PowerShell or CMD with just:

```cmd
run-hydra-windows
```

If startup fails, the launcher keeps the console open and shows the failure (plus the host error-log path when available) instead of closing immediately. Internal QA/build helpers may still use PowerShell, but there is no paired `run-app-windows.ps1`, shortcut-installer `.ps1`, or root launcher `.ps1` for users to manage.

The Windows host executable embeds `examples/hydra-gui/assets/hydra.ico`, so process viewers such as Task Manager can display the HYDRA icon. The dedicated browser app window uses the same manifest/favicon artwork for its window/taskbar identity.

Linux:

```bash
./examples/hydra-gui/scripts/install-linux-desktop.sh
```

Then launch **HYDRA** from the desktop application menu. The launcher uses a dedicated Chromium-family app window with `WM_CLASS=hydra-msg`, matching the installed desktop entry so supported taskbars/docks display the HYDRA icon rather than the browser's generic icon.

## Carrier and privacy experience

The carrier selector is always beside the composer and intentionally uses five simple choices: **encrypted**, **stego-instant**, **stego-unicode**, **stego hybrid**, and **stego-ai**. Direct/group packet internals remain hidden from the normal chat flow.

For steganographic direct and text-only group messages, the chat bubble shows the exact carrier text that crossed the demo relay by default, both for the sender and recipient. The UI does not add a stego badge, hint, or reply button. Clicking that bubble reveals the decoded HYDRA plaintext; clicking it again returns to the carrier. The compact **S** button beside the privacy control toggles all stego messages between carrier and decoded views at once. This keeps the ordinary transcript from advertising which individual messages are steganographic.

The `***` button beside the text box is a local privacy-display mode. While enabled, typed characters are rendered as `*` and all message bodies are masked locally. Clicking an individual message reveals its decoded text for that bubble; clicking again masks it. While privacy mode is active, the global **S** control affects only carrier messages: it toggles every steganographic message between `*` and decoded plaintext while ordinary messages remain masked. The mask changes only the local presentation and does not change the encrypted/steganographic bytes sent to peers.

Incoming and outgoing messages remain color-coded and aligned to opposite sides. The message list owns scrolling while the composer stays in a fixed bottom grid row, including the mobile layout, so a long conversation cannot push the text box off screen. Carrier-message inner scroll positions and the transcript scroll anchor are preserved across view changes and background updates. The GUI also persists its message-view sidecar in IndexedDB alongside persistent HYDRA state, so exact carrier text/profile metadata and outgoing transcript entries survive reload instead of falling back to decoded-only HYDRA history.

Every message has a small actions menu. It closes when you click elsewhere, press **Escape**, scroll the transcript, switch conversations, or open another message menu. **Remove from this device** deletes only that browser's copy. **Request removal for everyone** sends a consent request to the other currently connected participants. No remote copy is deleted automatically: each participant may remove it, keep it, or ignore the request. A demo-relay correlation tag identifies the same message without changing the HYDRA packet or stego carrier payload itself.

For text-only groups, the demo encrypts a compact per-member HYDRA message and then applies the selected carrier independently for each recipient; attachments continue through normal padded lobby packets. **stego-instant** needs no model. Selecting **stego-unicode**, **stego hybrid**, or **stego-ai** reveals one compact **AI cover model** selector below the composer carrier control. Selecting a model automatically bootstraps the local Python runtime when needed and downloads/loads the pinned model. The model process is shared by browsers connected to this example host.

## Validation

The repository example gate checks the host, tests the LAN hub, smoke-runs the web server, and builds the WASM package:

```bash
./qa/ci/core/check-examples.sh
```

or:

```powershell
.\qa\ci\core\check-examples.ps1
```
