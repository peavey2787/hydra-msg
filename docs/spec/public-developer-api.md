# HYDRA-MSG Public Developer API

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../impl/message-flow/README.md)
- [Spec docs and repo structure](README.md)
- [Crates](../../crates/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](public-developer-api.md)
- [Benchmark notes](../validation/benchmark-results.md)

Status: **v1 public API frozen** for the `hydra-msg` facade crate. This freezes the app-facing SDK surface, not the full protocol/specification release; protocol freeze and production release still depend on the validation gates in `docs/validation/release-criteria.md`.

Goal: make HYDRA simple for app developers. A developer should be able to open HYDRA, create or restore an identity, add contacts, handshake, send messages, receive messages, use lobbies, back up data, rotate passwords, preview shareable inputs before importing them, and run basic diagnostics without seeing cryptographic internals, wire-format details, padding classes, chunks, ratchets, sessions, or transport logic.

HYDRA is transport-agnostic. WebRTC, libp2p, HTTP, QR codes, files, relays, Kaspa pointers, mailboxes, and manual copy/paste are carriers only. They move opaque HYDRA bytes. They are not protocol authority.

Normal send/receive is key/session based. HYDRA can support anonymous chat designs, but the anonymity property comes from how the app provisions identities, contact cards, carriers, mailbox aliases, and authorization. Use the following wording consistently:

```text
Anonymous to the other user:
  Use a one-time HYDRA identity/contact card for that chat.

Unlinkable across chats:
  Use fresh identities per chat/lobby and do not reuse contact cards, invites, mailbox IDs, app-account handles, or carrier routing identifiers.

Anonymous to the server/relay:
  A relay only needs opaque HYDRA bytes, but it may still see timing, IP addresses, mailbox IDs, request sizes, chunk counts, and routing metadata unless the carrier hides those too.

Anonymous to the network:
  Requires a Tor/I2P/mixnet/proxy/relay design. HYDRA encryption by itself does not hide network endpoints or traffic patterns.

Anonymous-but-authorized:
  The current facade has a one-time bearer-token stopgap for scope/action checks. Stronger unlinkable issuance/redemption requires blind credentials, zero-knowledge proofs, or another dedicated eligibility mechanism. Plain contact cards authenticate keys; they do not prove private eligibility.
```

Do not describe the normal message path as inherently anonymous. A normal HYDRA conversation is still based on peer key material, a contact/session record, and decryptable envelopes for the intended recipient.

## Current facade privacy boundaries

| Area | Current status |
|---|---|
| Handshake confidentiality | `init_handshake`, `reply_handshake`, and `finish_handshake` use an authenticated hybrid exchange: ML-DSA identity signatures, ephemeral X25519, ephemeral ML-KEM-768, transcript binding, and answer confirmation. |
| Normal message content | `send` returns one or more opaque encrypted packets for the app carrier. The receiver must have the matching contact/session state to decrypt. |
| Packet sizing | HYDRA uses strict metadata minimization by default. Outbound packets are fixed-size HYDRA envelope classes, and larger valid messages automatically become more fixed-size packets. Apps never see chunk records or padding classes. Packet count and timing still leak. |
| Backup export | `export_backup` encrypts a validated state snapshot into a chunked encrypted backup container under the supplied backup password. The final storage chunk is padded, and larger backups add more fixed-size chunks internally. Chunk count, file existence, KDF metadata, and backup timing still leak. |
| Normal local state | `state.hydra` is an opaque authenticated-encrypted chunked storage container. `Hydra::open(data_dir, state_password)` and `Hydra::open_default(state_password)` require the state password up front. |
| Identity passwords | Identity seeds, state files, and backups are wrapped with AEAD using per-record scrypt parameters and random salts before key derivation. Weak user passwords can still be brute-forced offline, so applications should enforce strong password policy where appropriate. |
| Contact cards | Default contact cards expose the active identity public verification key only. The contact id/fingerprint and safety code are derived locally from that key. `create_labeled_contact_card` intentionally adds a label. Reusing the same identity/card can link chats. |
| Lobby invites | Default lobby invites expose only the lobby id and max-member policy. `create_labeled_lobby_invite` intentionally adds the label, and `create_lobby_member_invite` intentionally adds the member list. Reusing the same lobby/invite can link activity. |
| Lobby recipient tags | `HydraLobbyEnvelope::recipient()` is a direct app-local routing hint for a per-member encrypted copy. `HydraLobbyEnvelope::routing_hint()` is a randomized opaque hint for carriers that can route through mailbox aliases. Neither is anonymous routing by itself, and neither must be treated as authentication. |
| Anonymous authorization | `issue_anonymous_auth_token`, `accept_anonymous_auth_token`, and `revoke_anonymous_auth_token` provide a bounded one-time bearer-token stopgap for scope/action authorization without exposing contact or identity ids. This is not blind issuance or network anonymity. See [Anonymous authorization](anonymous-authorization.md). |

For unlinkable app designs today, use `create_one_time_contact_card` for fresh chat identities and `create_one_time_lobby_invite` for fresh lobby invites, then pair those with carrier/mailbox identifiers that are not reused across chats.

## Public API rules

The public API has no advanced mode. The frozen v1 API is the crate-root facade and helper types listed in this document. New app-facing methods, public modules, protocol knobs, storage/checkpoint APIs, or advanced configuration APIs require an explicit v1.1+ API review instead of being added silently.

Do not add these to the normal public facade:

```text
HydraConfig
HydraProfile
HydraBuilder
protocol_info
supported_suites
export_session
import_session
send_with_options
receive_with_options
chunk_payload
send_chunk
receive_chunk
reassemble_chunks
checkpoint_lobby
verify_lobby_checkpoint
export_lobby_state
import_lobby_state
```

If a feature requires one of those concepts internally, keep it internal. The public facade must remain simple.

`hydra-msg::limits` is intentionally **not** public. Resource ceilings, parser budgets, chunk sizes, and DoS guardrails are implementation details. App developers should use documented public methods such as `set_packet_size()` and `packet_size()`, plus ordinary error handling, instead of importing internal constants.

## Open / storage path

```rust
Hydra::open(data_dir, state_password)
Hydra::open_default(state_password)
hydra.data_dir()
hydra.change_state_password(old_password, new_password)
```

Example:

```rust
use hydra_msg::Hydra;

let mut hydra = Hydra::open("./hydra-msg-data", "state-password")?;
hydra.change_state_password("state-password", "new-state-password")?;
```

`hydra-msg-data/` is the default local development data directory and must stay ignored by git. The state password is required before any normal local state can be loaded or written.

Native/CLI local state is persisted as one opaque authenticated-encrypted chunked container in `state.hydra`. HYDRA pads the final encrypted storage chunk and adds more fixed-size chunks internally when state grows. The native adapter only stores opaque encrypted bytes and a rollback sidecar; it does not parse contacts, identities, messages, attachments, lobbies, anonymous-authorization state, or decrypted snapshot records. Missing state creates a new encrypted store. Wrong passwords, corrupt envelopes, malformed snapshots, stale generations, and filesystem errors fail closed.

`change_state_password(old_password, new_password)` rewraps future local state persistence under a fresh state KDF/key and commits through the normal persistence path. If commit fails, HYDRA restores the previous state key/KDF in memory and returns the error.

The native rollback guard is local-file based. It catches straightforward replay of older local state files but is not a complete anti-rollback proof against a malicious host, restored filesystem image, or backup replay. Stronger freshness requires peer revalidation, hardware monotonic storage, an authenticated service, or another external freshness anchor.

Browser/WASM persistence is intentionally platform-specific because IndexedDB is asynchronous. Browser apps that need durable state use:

```javascript
const hydra = await WasmHydra.openPersistent('default-profile', 'state-password');
// ...mutating calls...
await hydra.flush();
```

Apps that intentionally do not need durable browser state, such as tests and benchmarks, use:

```javascript
const hydra = WasmHydra.openEphemeral('benchmark-profile', 'state-password');
```

`openPersistent(name, password)` stores opaque authenticated-encrypted chunked state bytes in IndexedDB. `flush()` is the explicit durable commit boundary. Browser flushes use a non-secret profile-revision compare-and-swap so multiple tabs cannot silently overwrite each other with last-writer-wins state. A stale tab receives an error, remains dirty, and must reopen or ask the user how to resolve unsaved local changes. The binding exposes no ambiguous WASM `open()` or `openDefault()` aliases. `localStorage` must not be used for HYDRA state.

Browser lifecycle diagnostics are intentionally small:

```javascript
await WasmHydra.browserLifecycleStatus();
await WasmHydra.requestPersistentStorage();
```

Apps should use these to warn about private browsing, storage eviction risk, quota pressure, persistent-storage denial, and mobile background/kill behavior. HYDRA never treats those APIs as a cryptographic freshness source; exported encrypted backups remain the recovery path.

## Identity

```rust
hydra.generate_id(password)
hydra.import_id(bytes, password)
hydra.export_id(id, password)
hydra.change_id_password(id, old_password, new_password)

hydra.list_ids()
hydra.get_id(id)
hydra.active_id()

hydra.set_active_id(id, password)
hydra.unlock_id(id, password)
hydra.lock_id(id)
hydra.lock_active_id()

hydra.rename_id(id, label)
hydra.delete_id(id, password)
```

Purpose: create, restore, export, rotate identity passwords, unlock, lock, rename, delete, and switch identities.

`change_id_password(id, old_password, new_password)` rewraps the identity seed under a fresh identity KDF/key. The identity id and public key do not change. If persistence fails after rewrap, HYDRA restores the previous in-memory snapshot before returning the error.

## Contacts

```rust
hydra.create_contact_card()
hydra.create_labeled_contact_card(label)
hydra.create_one_time_contact_card(identity_password)
hydra.create_contact_invite()
hydra.preview_contact_card(contact_card)

hydra.add_contact(contact_card)
hydra.import_contacts(bytes)
hydra.export_contacts()

hydra.list_contacts()
hydra.get_contact(contact_id)
contact.safety_code()

hydra.verify_contact(contact_id, safety_code)
hydra.unverify_contact(contact_id)

hydra.rename_contact(contact_id, label)
hydra.remove_contact(contact_id)

hydra.block_contact(contact_id)
hydra.unblock_contact(contact_id)
```

Purpose: create minimized or explicitly labeled shareable contact cards, create fresh one-time cards for unlinkable chat setup, preview a card before mutating local state, add contacts, review safety codes, verify contacts, export/import contacts, and manage blocked contacts.

`preview_contact_card(contact_card)` decodes and validates a card and returns the same `HydraContact` summary that `add_contact()` would add, but it does not persist or mutate local state.

Trust model:

```text
verified = safety code matched
blocked = do not receive from or send to this contact
```

Do not add separate `trust_contact` / `untrust_contact` methods unless they become meaningfully different from verification.

## Handshake / sessions

```rust
let offer = hydra.init_handshake(contact_id)?;
let answer = hydra.reply_handshake(offer)?;
hydra.finish_handshake(answer)?;

hydra.session_status(contact_id)
hydra.rekey_session(contact_id)
hydra.close_session(contact_id)
```

Public rule:

```text
init_handshake(contact_id) creates the initiator's outbound handshake offer.
reply_handshake(offer) verifies the signed offer, creates the signed responder answer, and creates/activates the responder-side session.
finish_handshake(answer) verifies the signed answer and creates/activates the initiator-side session.
```

The facade handshake is an authenticated hybrid exchange. The offer carries the initiator identity verification key, an ML-DSA signature, an ephemeral X25519 public key, and an ephemeral ML-KEM-768 encapsulation key. The answer carries the responder identity verification key, an ML-DSA signature bound to the offer, an ephemeral X25519 public key, an ML-KEM-768 ciphertext, and a confirmation tag. The session secret is derived from the X25519 shared secret, the ML-KEM shared secret, and the signed transcript; the confirmation tag proves both sides derived the same answer transcript secret before the initiator installs the session.

After the handshake flow completes, the contact is ready for message delivery. App developers must not manually create sessions or manage fragment records. Carriers can see handshake bytes and timing/routing metadata, but they do not receive the session secret.

## Messages, payloads, and attachments

`send()` accepts a `HydraMessage`. Simple plaintext, bytes, and attachments are all just message payloads at the public API level.

Apps with carrier-size or padding constraints configure one app-visible packet ceiling and keep using the normal message API:

```rust
hydra.set_packet_size(56 * 1024)?;
let current_packet_cap = hydra.packet_size();

let packets = hydra.send(contact_id, HydraMessage::text("hello"))?;
for packet in packets {
    carrier.send(packet.as_bytes())?;
}

if let Some(received) = peer.receive(incoming_packet)? {
    println!("{}", received.text()?);
}
```

```rust
hydra.set_packet_size(bytes)
hydra.packet_size()
hydra.send(contact_id, message)
hydra.receive(packet)
```

`set_packet_size(bytes)` is the hard app-visible transport packet ceiling. HYDRA v1 has fixed padded packet classes: Lite is 4 KiB, Standard is 32 KiB, and Full is 144 KiB. A 56 KiB transport cap maps to Standard packets internally because Standard is the largest class that fits under that ceiling. If a message is too large for one selected packet class, HYDRA internally splits it and `send()` returns multiple opaque packets.

`packet_size()` returns the current app-visible packet ceiling.

The public facade intentionally does not expose chunk records or fragment ids. Apps loop over the packets returned by `send()` and feed each incoming packet to `receive()`. `receive()` returns `None` while HYDRA is waiting for more packets and `Some(message)` when reassembly completes.

### Text message

```rust
let packets = hydra.send(contact_id, HydraMessage::text("hello"))?;
```

### Bytes message

```rust
let packets = hydra.send(contact_id, HydraMessage::bytes(bytes_here))?;
```

### Message with file attachment

```rust
let packets = hydra.send(
    contact_id,
    HydraMessage::text("photo attached")
        .attach_file("./photo.jpg")?
)?;
```

### Message with in-memory bytes attachment

```rust
let packets = hydra.send(
    contact_id,
    HydraMessage::text("raw bytes attached")
        .attach_bytes("data.bin", bytes_here)?
)?;
```

### Struct-style construction

```rust
let message = HydraMessage {
    plaintext: b"hello".to_vec(),
    attachments: vec![
        HydraAttachment::from_file("./photo.jpg")?,
        HydraAttachment::from_bytes(bytes_here)?.with_filename("data.bin")?,
    ],
};

let packets = hydra.send(contact_id, message)?;
```

### Receive

```rust
if let Some(data) = hydra.receive(packet)? {
    println!("{}", data.text()?);

    for attachment in data.attachments() {
        std::fs::write(attachment.filename(), attachment.bytes())?;
    }
}
```

The receive path distinguishes text payloads, raw bytes payloads, file-backed attachments, and byte-backed attachments after decryption. Internally, all of this can be packed, chunked, padded, encrypted, and reassembled however HYDRA requires. The app developer should not see those mechanics.

### Message history

```rust
hydra.list_messages(contact_id)
hydra.get_message(message_id)
hydra.delete_message(message_id)
hydra.clear_messages(contact_id)

hydra.export_messages()
hydra.import_messages(bytes)
```

Purpose: send/receive encrypted payloads and optionally store/export/import local message history.

## Groups / lobbies

```rust
let lobby = hydra.create_lobby(policy)?;
let invite = hydra.create_lobby_invite(lobby.id())?;
let labeled_invite = hydra.create_labeled_lobby_invite(lobby.id())?;
let member_invite = hydra.create_lobby_member_invite(lobby.id())?;
let one_time_invite = hydra.create_one_time_lobby_invite(max_members)?;
let preview = hydra.preview_lobby_invite(invite.as_bytes())?;

hydra.join_lobby(invite)
hydra.leave_lobby(lobby_id)

hydra.list_lobbies()
hydra.get_lobby(lobby_id)
hydra.lobby_members(lobby_id)

hydra.add_lobby_member(lobby_id, contact_id)
hydra.remove_lobby_member(lobby_id, contact_id)

let copies = hydra.send_lobby(lobby_id, message)?;
for copy in copies {
    // Prefer randomized routing hints or mailbox aliases when the carrier supports them.
    carrier.send(copy.routing_hint(), copy.into_envelope())?;
    // Use copy.recipient() only for direct/local routing; it is metadata-revealing.
}

if let Some(data) = hydra.receive_lobby(packet)? {
    println!("{}", data.text()?);
}

hydra.rekey_lobby(lobby_id)
hydra.close_lobby(lobby_id)
```

Purpose: create/join lobbies, preview invites before mutating local state, create minimized or explicitly metadata-bearing invites, create one-time lobby invites for unlinkable setup, manage members, send encrypted lobby messages, and receive encrypted lobby messages.

`preview_lobby_invite(invite)` decodes and validates an invite and returns the same `HydraLobby` summary that `join_lobby()` would add, but it does not persist or mutate local state.

`send_lobby` returns one or more encrypted packet copies with two visible routing helpers: `recipient()` for direct app-local routing and `routing_hint()` for carriers that support opaque mailbox aliases. `routing_hint()` is randomized per encrypted packet. Neither helper is protocol authority; the receiver authenticates the encrypted packet bytes, not the carrier-provided route metadata.

`create_lobby_invite` is minimized by default. Because it does not expose a member list, the joining app should add the inviter contact locally with `add_lobby_member(joined.id(), inviter_contact_id)` when it wants to accept messages from that inviter.

`receive_lobby` only accepts lobby payloads. A normal 1:1 message passed to `receive_lobby` must be rejected without being consumed, and lobby messages from contacts that are not members of the local lobby must be rejected.

Do not add checkpoint, AOL2 state, predicate, or lobby-state import/export APIs to `hydra-msg`. Those belong above HYDRA in Kaspakinesis/AOL2-specific layers.

## Anonymous authorization

```rust
let policy = HydraAnonymousAuthPolicy::new("private-lobby", "join")
    .with_expiry(expires_at_unix_seconds);
let token = hydra.issue_anonymous_auth_token(policy)?;
let nullifier = hydra.anonymous_auth_nullifier(&token)?;
let grant = hydra.accept_anonymous_auth_token(
    token,
    "private-lobby",
    "join",
    now_unix_seconds,
)?;
hydra.revoke_anonymous_auth_token(token_to_revoke, "private-lobby", "join")?;
```

Purpose: provide a bounded one-time authorization token that is separate from HYDRA contact identity and message encryption. Tokens authorize a scope/action pair, optionally expire, and produce verifier-side nullifiers so accepted or revoked tokens cannot be reused by the same verifier.

Privacy boundary: this is a bearer-token stopgap, not blind issuance. It does not reveal contact ids, identity ids, lobby member ids, session ids, or message ids, and repeated issuance for the same scope/action produces fresh token bytes and fresh nullifiers. It can still be correlated by whoever sees issuance and redemption metadata, network metadata, app account handles, reused scopes, reused tokens, nullifier logs, or reused mailbox/relay identifiers.

Apps that need anonymous-but-authorized access stronger than bearer tokens need a separate blind-credential or proof layer. See [Anonymous authorization](anonymous-authorization.md).

## Backup / restore

```rust
hydra.export_backup(password)
hydra.import_backup(bytes, password)
hydra.verify_backup(bytes, password)
```

The backup can internally include identities, contacts, messages, lobbies, and local settings. `verify_backup(bytes, password)` authenticates the backup and validates the decrypted snapshot without mutating local state. `import_backup(bytes, password)` is a verified restore/replacement flow. On Native/CLI it commits through normal encrypted local persistence before returning success; if the native commit fails, the facade restores the previous in-memory snapshot before returning the error. On WASM, `importBackup(bytes, password)` marks the persistent wrapper dirty and the app must call `await hydra.flush()` to commit the restored encrypted chunked state container to IndexedDB.

The public API stays simple. Backups are for explicit user-controlled portability and recovery, not the hidden app persistence layer.

## Production diagnostics

```rust
hydra.storage_status()
hydra.benchmark()
```

`storage_status()` returns a redacted production-safe storage summary. It does not return a `Result`, and it does not expose counts or state generation.

`benchmark()` returns a small benchmark report for local diagnostics.

## Debug-only public APIs

These APIs are public because app developers need them for tests, local diagnostics, and support tooling, but they are not safe production telemetry surfaces.

```rust
hydra.storage_debug_status()
```

`storage_debug_status()` exposes identity/contact/session/message/lobby counts and the local state generation. Do not log it in production, do not send it to a server by default, and do not display it in privacy-sensitive UI.

## Browser persistence API boundary

The normal native `hydra-msg` facade does not expose checkpoint APIs, raw state-snapshot bytes, or encrypted snapshot import/export methods. Browser persistence is implemented inside `hydra-msg` with WASM-only persistent open/flush helpers that own IndexedDB loading, compare-and-swap writes, and generation rollback on failed browser flushes.

Browser app developers should normally use the JavaScript wrapper methods `WasmHydra.openPersistent(...)`, `hydra.flush()`, and `WasmHydra.deletePersistent(...)`. Rust/WASM adapter code may use the WASM-only `Hydra::open_browser_persistent(...)`, `hydra.flush_browser_persistent(...)`, and `Hydra::delete_browser_persistent(...)` APIs. None of those APIs expose raw snapshot bytes to app developers.

Rust native app developers should use `Hydra::open`, `Hydra::open_default`, `export_backup`, and `import_backup`. Do not build app storage around private state files or snapshot internals.

## Complete public API list

```rust
// Open / state password
Hydra::open(data_dir, state_password)
Hydra::open_default(state_password)
hydra.data_dir()
hydra.change_state_password(old_password, new_password)

// Browser/WASM persistent state boundary, cfg(target_arch = "wasm32")
Hydra::open_browser_persistent(name, state_password)
Hydra::delete_browser_persistent(name)
hydra.flush_browser_persistent(name, expected_revision)
Hydra::browser_lifecycle_status()
Hydra::request_persistent_storage()

// Identity
hydra.generate_id(password)
hydra.import_id(bytes, password)
hydra.export_id(id, password)
hydra.change_id_password(id, old_password, new_password)
hydra.list_ids()
hydra.get_id(id)
hydra.active_id()
hydra.set_active_id(id, password)
hydra.unlock_id(id, password)
hydra.lock_id(id)
hydra.lock_active_id()
hydra.rename_id(id, label)
hydra.delete_id(id, password)

// Contacts
hydra.create_contact_card()
hydra.create_labeled_contact_card(label)
hydra.create_one_time_contact_card(identity_password)
hydra.create_contact_invite()
hydra.preview_contact_card(contact_card)
hydra.add_contact(contact_card)
hydra.import_contacts(bytes)
hydra.export_contacts()
hydra.list_contacts()
hydra.get_contact(contact_id)
hydra.verify_contact(contact_id, safety_code)
hydra.unverify_contact(contact_id)
hydra.rename_contact(contact_id, label)
hydra.remove_contact(contact_id)
hydra.block_contact(contact_id)
hydra.unblock_contact(contact_id)

// Handshake / sessions
hydra.init_handshake(contact_id)
hydra.reply_handshake(offer)
hydra.finish_handshake(answer)
hydra.session_status(contact_id)
hydra.rekey_session(contact_id)
hydra.close_session(contact_id)

// Messaging
hydra.set_packet_size(bytes)
hydra.packet_size()
hydra.send(contact_id, message)
hydra.receive(packet)
hydra.list_messages(contact_id)
hydra.get_message(message_id)
hydra.delete_message(message_id)
hydra.clear_messages(contact_id)
hydra.export_messages()
hydra.import_messages(bytes)

// Groups / lobbies
hydra.create_lobby(policy)
hydra.create_lobby_invite(lobby_id)
hydra.create_labeled_lobby_invite(lobby_id)
hydra.create_lobby_member_invite(lobby_id)
hydra.create_one_time_lobby_invite(max_members)
hydra.preview_lobby_invite(invite)
hydra.join_lobby(invite)
hydra.leave_lobby(lobby_id)
hydra.list_lobbies()
hydra.get_lobby(lobby_id)
hydra.lobby_members(lobby_id)
hydra.add_lobby_member(lobby_id, contact_id)
hydra.remove_lobby_member(lobby_id, contact_id)
hydra.send_lobby(lobby_id, message)
hydra.receive_lobby(packet)
hydra.rekey_lobby(lobby_id)
hydra.close_lobby(lobby_id)

// Anonymous authorization
hydra.issue_anonymous_auth_token(policy)
hydra.anonymous_auth_nullifier(token)
hydra.accept_anonymous_auth_token(token, expected_scope, expected_action, now_unix_seconds)
hydra.revoke_anonymous_auth_token(token, expected_scope, expected_action)

// Backup / restore
hydra.export_backup(password)
hydra.import_backup(bytes, password)
hydra.verify_backup(bytes, password)

// Production diagnostics
hydra.storage_status()
hydra.benchmark()

// Debug-only public diagnostics
hydra.storage_debug_status()
```

## Public helper types and methods

The facade also exposes small value types needed to use the methods above:

```rust
IdentityId::from_hex(hex)
IdentityId::from_bytes(bytes)
identity_id.hex()
identity_id.bytes()

ContactId::from_hex(hex)
ContactId::from_bytes(bytes)
contact_id.hex()
contact_id.bytes()

LobbyId::from_hex(hex)
LobbyId::from_bytes(bytes)
lobby_id.hex()
lobby_id.bytes()

HydraIdentitySummary::id()
HydraIdentitySummary::label()
HydraIdentitySummary::unlocked()

HydraContact::id()
HydraContact::label()
HydraContact::public_key()
HydraContact::verified()
HydraContact::blocked()
HydraContact::safety_code()

HydraOneTimeContactCard::identity_id()
HydraOneTimeContactCard::card()
HydraOneTimeContactCard::into_card()
HydraOneTimeContactCard::into_parts()

HydraLobbyPolicy::new(label, max_members)
HydraLobbyPolicy::default()

HydraLobby::id()
HydraLobby::policy()
HydraLobby::members()

HydraLobbyInvite::as_bytes()
HydraLobbyInvite::into_bytes()
HydraLobbyInvite::from_bytes(bytes)

HydraOneTimeLobbyInvite::lobby_id()
HydraOneTimeLobbyInvite::invite()
HydraOneTimeLobbyInvite::into_invite()
HydraOneTimeLobbyInvite::into_parts()

HydraEnvelope::as_bytes()
HydraEnvelope::into_bytes()
HydraEnvelope::from_bytes(bytes)

HandshakeOffer::as_bytes()
HandshakeOffer::into_bytes()
HandshakeOffer::from_bytes(bytes)

HandshakeAnswer::as_bytes()
HandshakeAnswer::into_bytes()
HandshakeAnswer::from_bytes(bytes)

MessageId::from_u64(value)
message_id.value()

HydraAttachmentSource::File
HydraAttachmentSource::Bytes

HydraMessage::text(text)
HydraMessage::bytes(bytes)
HydraMessage::attach_file(path)
HydraMessage::attach_bytes(filename, bytes)
HydraMessage::plaintext()
HydraMessage::attachments()

HydraAttachment::from_file(path)
HydraAttachment::from_bytes(bytes)
HydraAttachment::from_named_bytes(filename, bytes)
HydraAttachment::with_filename(filename)
HydraAttachment::filename()
HydraAttachment::bytes()
HydraAttachment::source()
HydraAttachment::is_file()
HydraAttachment::is_bytes()

ReceivedHydraMessage::from()
ReceivedHydraMessage::message_id()
ReceivedHydraMessage::lobby_id()
ReceivedHydraMessage::plaintext()
ReceivedHydraMessage::text()
ReceivedHydraMessage::attachments()

HydraLobbyRoutingHint::from_bytes(bytes)
hydra_lobby_routing_hint.bytes()

HydraLobbyEnvelope::recipient()
HydraLobbyEnvelope::routing_hint()
HydraLobbyEnvelope::envelope()
HydraLobbyEnvelope::into_envelope()
HydraLobbyEnvelope::into_parts()
HydraLobbyEnvelope::into_routed_parts()

HydraAnonymousAuthPolicy::new(scope, action)
HydraAnonymousAuthPolicy::with_expiry(expires_at_unix_seconds)
HydraAnonymousAuthPolicy::scope()
HydraAnonymousAuthPolicy::action()
HydraAnonymousAuthPolicy::expires_at_unix_seconds()

HydraAnonymousAuthToken::as_bytes()
HydraAnonymousAuthToken::into_bytes()
HydraAnonymousAuthToken::from_bytes(bytes)
HydraAnonymousAuthGrant::policy()
HydraAnonymousAuthNullifier::from_bytes(bytes)
hydra_anonymous_auth_nullifier.bytes()
HydraAnonymousAuthNullifier::hex()
HydraAnonymousAuthGrant::nullifier()

HydraStorageStatus { data_dir, encrypted_state }
HydraStorageDebugStatus {
  data_dir,
  identity_count,
  contact_count,
  session_count,
  message_count,
  lobby_count,
  encrypted_state,
  state_generation,
}

HydraBenchmarkReport {
  suite,
  iterations,
  handshake_avg_ms,
  send_receive_avg_ms,
}
```

## Internal-only implementation areas

This section names implementation responsibilities that must stay behind the public facade. It is not an API list and it intentionally avoids fake module paths or function names. If an internal responsibility is implemented across several crates or folded into higher-level code, that is fine; do not create extra code paths just to match documentation wording.

### Crypto internals

```text
identity key generation
identity signatures and verification
ML-KEM key generation, encapsulation, and decapsulation
X25519 ephemeral exchange
handshake secret derivation
session/message key derivation
route tag derivation
AEAD seal/open
secure random generation
constant-time comparisons where required by the threat model
```

### Handshake internals

```text
offer construction/parsing/validation
answer construction/parsing/validation
transcript construction and verification
session derivation from transcript
answer confirmation
```

### Session / ratchet internals

```text
session creation/loading/saving/deletion
send-state advancement
receive-state advancement
rekey/close operations
replay checks
skipped-key storage and consumption
receive route-tag indexing
```

### Envelope and packet internals

```text
envelope encoding/decoding
fixed envelope-class selection
payload padding/unpadding
outer-header encoding/decoding
protected-record encoding/decoding
envelope-size validation
route-tag validation
fragment record encoding/decoding
fragment reassembly
```

### Payload / attachment internals

```text
message packing/unpacking
attachment packing/unpacking
payload fragmentation and reassembly
payload hashing where needed
attachment file/byte handling
resource-limit validation
```

### Contact and identity internals

```text
contact card encoding/decoding/validation
safety-code computation and verification
contact storage records
identity vault records
identity encryption/decryption
identity import/export records
unlock/lock memory handling
password checks and password rewrapping
```

### Storage internals

```text
native state-file opening/writing
chunked encrypted state containers
chunked encrypted backup containers
rollback sidecar checks
crash-consistent temp-write/sync/rename behavior
backup export/import validation
redacted and debug storage status construction
```

### Group / lobby internals

```text
group-state creation
lobby policy validation
lobby invite encoding/decoding
member add/remove operations
group/lobby key rotation
group message encryption/decryption
membership and replay evidence validation
```

### Benchmark internals

```text
handshake benchmark execution
message benchmark execution
storage benchmark execution
benchmark report formatting
```

## Mental model

Public API:

```text
open, identity, contacts, handshake, send, receive, lobby, anonymous authorization, backup, production status, debug status, benchmark
```

Internal implementation:

```text
crypto, ratchets, sessions, envelopes, padding, chunks, storage, vaults, group keys, replay windows, route indexes, rollback guards
```

The app developer should never need to see chunks, padding classes, suite selection, protocol details, checkpoint verification, lobby state import/export, or advanced configuration.

## JavaScript / WASM facade

The WASM binding mirrors the same simple API shape from `crates/hydra-msg-wasm` and adds an explicit async browser persistence boundary for IndexedDB.

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = await WasmHydra.openPersistent('default-profile', 'state-password');
const id = hydra.generateId('password');
hydra.setActiveId(id, 'password');
await hydra.flush();

const card = hydra.createContactCard();
const preview = hydra.previewContactCard(card);
const contactId = hydra.addContact(card);
const safetyCode = hydra.contactSafetyCode(contactId);
hydra.verifyContact(contactId, safetyCode);
await hydra.flush();

const offer = hydra.initHandshake(contactId);
const answer = hydra.replyHandshake(offer);
hydra.finishHandshake(answer);
await hydra.flush();

const packets = hydra.send(
  contactId,
  WasmHydraMessage.text('hello').attachBytes('data.bin', new Uint8Array([1, 2, 3]))
);
await hydra.flush();
let data = null;
for (const packet of packets) {
  data = hydra.receive(packet) || data;
}
await hydra.flush();
console.log(data.text());
```

Browser persistence stores opaque authenticated-encrypted chunked local state containers in IndexedDB. `flush()` is explicit and final for this milestone: synchronous mutating calls, including `importBackup(bytes, password)`, mark the wrapper dirty, and apps call `await hydra.flush()` when they want to commit durable encrypted state. `WasmHydra.openEphemeral(name, password)` is available for tests and benchmarks that intentionally do not need durable state; there are no ambiguous WASM `open()` or `openDefault()` aliases. The JS/WASM API must not expose advanced protocol controls. The only transport sizing control is `setPacketSize`; `packetSize()` reads the current ceiling. `send()` returns one or more opaque packets, and `receive()` returns `null` until reassembly completes. See `docs/impl/wasm-javascript-bindings.md`.

Additional WASM-specific methods include:

```javascript
WasmHydra.openPersistent(name, password)
WasmHydra.openEphemeral(name, password)
WasmHydra.deletePersistent(name)
WasmHydra.browserLifecycleStatus()
WasmHydra.requestPersistentStorage()

hydra.flush()
hydra.isPersistent()
hydra.isDirty()
hydra.persistentRevision()
hydra.changeStatePassword(oldPassword, newPassword)
hydra.storageStatus()
hydra.storageDebugStatus()

hydra.setPacketSize(bytes)
hydra.packetSize()

hydra.changeIdPassword(idHex, oldPassword, newPassword)
hydra.createLabeledContactCard(label)
hydra.createOneTimeContactCard(password)
hydra.previewContactCard(cardBytes)
hydra.createLabeledLobbyInvite(lobbyIdHex)
hydra.createLobbyMemberInvite(lobbyIdHex)
hydra.createOneTimeLobbyInvite(maxMembers)
hydra.previewLobbyInvite(inviteBytes)
copy.routingHint()
copy.routingHintHex()
```

## Metadata-minimized defaults

HYDRA uses strict metadata minimization by default. Outbound messages use fixed-size encrypted packets and automatically add more chunks when a valid message does not fit one packet. Applications should not implement their own privacy-size overflow handling.

For lobby delivery, prefer `routing_hint()` / `routingHint()` or mailbox aliases. `recipient()` is a direct-mode/local routing hint and is not privacy-preserving.

`storage_status()` / `storageStatus()` is redacted. Use `storage_debug_status()` / `storageDebugStatus()` only for tests and local diagnostics, and do not log debug status in production.
