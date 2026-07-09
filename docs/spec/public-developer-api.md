# HYDRA-MSG Public Developer API

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../impl/message-flow/README.md)
- [Spec docs and repo structure](README.md)
- [Crates](../../crates/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](public-developer-api.md)
- [Benchmark notes](../validation/benchmark-results.md)

Status: target API for the `hydra-msg` facade crate.

Goal: make HYDRA simple for app developers. A developer should be able to open HYDRA, create or restore an identity, add contacts, handshake, send messages, receive messages, use lobbies, back up data, and run basic diagnostics without seeing cryptographic internals, wire-format details, padding classes, chunks, ratchets, sessions, or transport logic.

HYDRA is transport-agnostic. WebRTC, libp2p, HTTP, QR codes, files, relays, Kaspa pointers, mailboxes, and manual copy/paste are carriers only. They move opaque HYDRA bytes. They are not protocol authority.

Normal send/receive is key/session based. HYDRA can support anonymous chat designs, but the anonymity property comes from how the app provisions identities, contact cards, carriers, and authorization. Use the following wording consistently:

```text
Anonymous to the other user:
  Use a one-time HYDRA identity/contact card for that chat.

Unlinkable across chats:
  Use fresh identities per chat/lobby and do not reuse contact cards, invites, mailbox IDs, or app-account handles.

Anonymous to the server/relay:
  A relay only needs opaque HYDRA bytes, but it may still see timing, IP addresses, mailbox IDs, request sizes, and routing metadata unless the carrier hides that too.

Anonymous to the network:
  Requires a Tor/I2P/mixnet/proxy/relay design. HYDRA encryption by itself does not hide network endpoints or traffic patterns.

Anonymous-but-authorized:
  Requires a separate auth/privacy layer, such as proofs, blind credentials, tokens, or another unlinkable eligibility mechanism. Plain contact cards authenticate keys; they do not prove private eligibility.
```

Do not describe the normal message path as inherently anonymous. A normal HYDRA conversation is still based on peer key material, a contact/session record, and decryptable envelopes for the intended recipient.

## Current facade privacy boundaries

The public facade has these current implementation boundaries:

| Area | Current status |
|---|---|
| Handshake confidentiality | `init_handshake`, `reply_handshake`, and `finish_handshake` use an authenticated hybrid exchange: ML-DSA identity signatures, ephemeral X25519, ephemeral ML-KEM-768, transcript binding, and answer confirmation. |
| Normal message content | `send` returns opaque encrypted envelope bytes for the app carrier. The receiver must have the matching contact/session state to decrypt. |
| Backup export | `export_backup` encrypts the state snapshot under the supplied backup password. |
| Normal local state | `state-v2.hydra` is authenticated-encrypted. `Hydra::open(data_dir, state_password)` and `Hydra::open_default(state_password)` require the state password up front. |
| Identity passwords | Identity seeds and state files are wrapped with AEAD, but the current facade password derivation is HKDF/SHA3 based and not memory-hard. Treat this as protection against casual disclosure, not enterprise-grade offline brute-force resistance, until Argon2id/scrypt hardening ships. |
| Contact cards | Contact cards intentionally expose the local label, public key, contact id/fingerprint, and safety code to whoever receives the card. Reusing the same card can link chats. |
| Lobby invites | Lobby invites intentionally expose the lobby id, label, max-member policy, and member list encoded into the invite. Reusing invites can link lobby activity. |
| Lobby recipient tags | `HydraLobbyEnvelope.recipient()` is an app/carrier routing hint for a per-member encrypted copy. It is not anonymous routing and must not be treated as authentication. |

For unlinkable app designs today, create fresh identities/contact cards/lobby invites manually and use carrier/mailbox identifiers that are not reused across chats. First-class one-time helpers remain future implementation work.

## 1. Public API rules

The public API has no advanced mode for v1.

Do not add these to the public facade:

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

## 2. Open / storage path

```rust
Hydra::open(data_dir, state_password)
Hydra::open_default(state_password)
hydra.data_dir()
```

Example:

```rust
use hydra_msg::Hydra;

let mut hydra = Hydra::open("./hydra-msg-data", "state-password")?;
```

`hydra-msg-data/` is the default local development data directory and must stay ignored by git. The state password is required before any normal local state can be loaded or written.

## 3. Identity

```rust
hydra.generate_id(password)?;
hydra.import_id(bytes, password)?;
hydra.export_id(id, password)?;

hydra.list_ids()?;
hydra.get_id(id)?;
hydra.active_id()?;

hydra.set_active_id(id, password)?;
hydra.unlock_id(id, password)?;
hydra.lock_id(id)?;
hydra.lock_active_id()?;

hydra.rename_id(id, label)?;
hydra.delete_id(id, password)?;
```

Purpose: create, restore, export, unlock, lock, rename, delete, and switch identities.

## 4. Contacts

```rust
hydra.create_contact_card()?;
hydra.create_contact_invite()?;

hydra.add_contact(contact_card)?;
hydra.import_contacts(bytes)?;
hydra.export_contacts()?;

hydra.list_contacts()?;
hydra.get_contact(contact_id)?;
contact.safety_code();

hydra.verify_contact(contact_id, safety_code)?;
hydra.unverify_contact(contact_id)?;

hydra.rename_contact(contact_id, label)?;
hydra.remove_contact(contact_id)?;

hydra.block_contact(contact_id)?;
hydra.unblock_contact(contact_id)?;
```

Purpose: create your shareable contact card, add contacts, review safety codes, verify contacts, export/import contacts, and manage blocked contacts.

Trust model for v1:

```text
verified = safety code matched
blocked = do not receive from or send to this contact
```

Do not add separate `trust_contact` / `untrust_contact` methods unless they become meaningfully different from verification.

## 5. Handshake / sessions

```rust
let offer = hydra.init_handshake(contact_id)?;
let answer = hydra.reply_handshake(offer)?;
hydra.finish_handshake(answer)?;

hydra.session_status(contact_id)?;
hydra.rekey_session(contact_id)?;
hydra.close_session(contact_id)?;
```

Public rule:

```text
init_handshake(contact_id) creates the initiator's outbound handshake offer.
reply_handshake(offer) verifies the signed offer, creates the signed responder answer, and creates/activates the responder-side session.
finish_handshake(answer) verifies the signed answer and creates/activates the initiator-side session.
```

The facade handshake is an authenticated hybrid exchange. The offer carries the initiator identity verification key, an ML-DSA signature, an ephemeral X25519 public key, and an ephemeral ML-KEM-768 encapsulation key. The answer carries the responder identity verification key, an ML-DSA signature bound to the offer, an ephemeral X25519 public key, an ML-KEM-768 ciphertext, and a confirmation tag. The session secret is derived from the X25519 shared secret, the ML-KEM shared secret, and the signed transcript; the confirmation tag proves both sides derived the same answer transcript secret before the initiator installs the session.

After the handshake flow completes, the contact is ready for `send()` and `receive()`. App developers must not manually create sessions. Carriers can see handshake bytes and timing/routing metadata, but they do not receive the session secret.

## 6. Messages, payloads, and attachments

`send()` accepts a `HydraMessage`. Simple plaintext, bytes, and attachments are all just message payloads at the public API level.

### Text message

```rust
let envelope = hydra.send(
    contact_id,
    HydraMessage::text("hello")
)?;
```

### Bytes message

```rust
let envelope = hydra.send(
    contact_id,
    HydraMessage::bytes(bytes_here)
)?;
```

### Message with file attachment

```rust
let envelope = hydra.send(
    contact_id,
    HydraMessage::text("photo attached")
        .attach_file("./photo.jpg")?
)?;
```

### Message with in-memory bytes attachment

```rust
let envelope = hydra.send(
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

let envelope = hydra.send(contact_id, message)?;
```

### Receive

```rust
let data = hydra.receive(envelope)?;

println!("{}", data.text()?);

for attachment in data.attachments() {
    std::fs::write(attachment.filename(), attachment.bytes())?;
}
```

The receive path must be robust enough to distinguish text payloads, raw bytes payloads, file-backed attachments, and byte-backed attachments after decryption. Internally, all of this can be packed, chunked, padded, encrypted, and reassembled however HYDRA requires. The app developer should not see those mechanics.

### Message history

```rust
hydra.list_messages(contact_id)?;
hydra.get_message(message_id)?;
hydra.delete_message(message_id)?;
hydra.clear_messages(contact_id)?;

hydra.export_messages()?;
hydra.import_messages(bytes)?;
```

Purpose: send/receive encrypted payloads and optionally store/export/import local message history.

## 7. Groups / lobbies

```rust
let lobby = hydra.create_lobby(policy)?;
let invite = hydra.create_lobby_invite(lobby.id())?;

hydra.join_lobby(invite)?;
hydra.leave_lobby(lobby_id)?;

hydra.list_lobbies()?;
hydra.get_lobby(lobby_id)?;
hydra.lobby_members(lobby_id)?;

hydra.add_lobby_member(lobby_id, contact_id)?;
hydra.remove_lobby_member(lobby_id, contact_id)?;

let copies = hydra.send_lobby(lobby_id, message)?;
for copy in copies {
    // `copy.recipient()` tells the app/carrier who should receive this opaque envelope.
    carrier.send(copy.recipient(), copy.into_envelope())?;
}

let data = hydra.receive_lobby(envelope)?;

hydra.rekey_lobby(lobby_id)?;
hydra.close_lobby(lobby_id)?;
```

Purpose: create/join lobbies, manage members, send encrypted lobby messages, and receive encrypted lobby messages.

`send_lobby` returns recipient-tagged encrypted envelope copies. This keeps the public API simple while still giving the app/carrier the routing hint it needs. The recipient tag is not protocol authority; the envelope bytes remain opaque HYDRA bytes.

`receive_lobby` only accepts lobby payloads. A normal 1:1 message passed to `receive_lobby` must be rejected without being consumed, and lobby messages from contacts that are not members of the local lobby must be rejected.

Do not add checkpoint, AOL2 state, predicate, or lobby-state import/export APIs to `hydra-msg`. Those belong above HYDRA in Kaspakinesis/AOL2-specific layers.

## 8. Backup / restore

```rust
hydra.export_backup(password)?;
hydra.import_backup(bytes, password)?;
hydra.verify_backup(bytes)?;
```

The backup can internally include identities, contacts, messages, lobbies, and local settings. The public API stays simple.

## 9. Diagnostics

```rust
hydra.storage_status()?;
hydra.benchmark()?;
```

These are the only required public diagnostics for v1.

## 10. Complete public v1 API list

```rust
// Open
Hydra::open(data_dir, state_password)
Hydra::open_default(state_password)
hydra.data_dir()

// Identity
hydra.generate_id(password)
hydra.import_id(bytes, password)
hydra.export_id(id, password)
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
hydra.create_contact_invite()
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
hydra.send(contact_id, message)
hydra.receive(envelope)
hydra.list_messages(contact_id)
hydra.get_message(message_id)
hydra.delete_message(message_id)
hydra.clear_messages(contact_id)
hydra.export_messages()
hydra.import_messages(bytes)

// Groups / lobbies
hydra.create_lobby(policy)
hydra.create_lobby_invite(lobby_id)
hydra.join_lobby(invite)
hydra.leave_lobby(lobby_id)
hydra.list_lobbies()
hydra.get_lobby(lobby_id)
hydra.lobby_members(lobby_id)
hydra.add_lobby_member(lobby_id, contact_id)
hydra.remove_lobby_member(lobby_id, contact_id)
hydra.send_lobby(lobby_id, message)
hydra.receive_lobby(envelope)
hydra.rekey_lobby(lobby_id)
hydra.close_lobby(lobby_id)

// Backup / restore
hydra.export_backup(password)
hydra.import_backup(bytes, password)
hydra.verify_backup(bytes)

// Diagnostics
hydra.storage_status()
hydra.benchmark()
```

## 11. Internal-only API areas

These are implementation areas, not normal public developer APIs.

### Crypto internals

```rust
internal::crypto::generate_identity_keypair()
internal::crypto::sign_identity()
internal::crypto::verify_identity_signature()
internal::crypto::kem_keygen()
internal::crypto::kem_encapsulate()
internal::crypto::kem_decapsulate()
internal::crypto::x25519_ephemeral()
internal::crypto::derive_handshake_secret()
internal::crypto::derive_session_keys()
internal::crypto::derive_message_key()
internal::crypto::derive_route_tag()
internal::crypto::aead_encrypt()
internal::crypto::aead_decrypt()
internal::crypto::secure_random()
internal::crypto::constant_time_eq()
```

### Handshake internals

```rust
internal::handshake::build_offer()
internal::handshake::parse_offer()
internal::handshake::validate_offer()
internal::handshake::build_answer()
internal::handshake::parse_answer()
internal::handshake::validate_answer()
internal::handshake::build_transcript()
internal::handshake::verify_transcript()
internal::handshake::derive_session_from_transcript()
internal::handshake::confirm_handshake()
```

### Session / ratchet internals

```rust
internal::session::create_session()
internal::session::load_session()
internal::session::save_session()
internal::session::delete_session()
internal::session::next_send_state()
internal::session::next_receive_state()
internal::session::rekey()
internal::session::close()
internal::session::replay_check()
internal::session::store_skipped_key()
internal::session::consume_skipped_key()
```

### Envelope internals

```rust
internal::envelope::encode_envelope()
internal::envelope::decode_envelope()
internal::envelope::select_envelope_class()
internal::envelope::pad_payload()
internal::envelope::unpad_payload()
internal::envelope::encode_outer_header()
internal::envelope::decode_outer_header()
internal::envelope::encode_protected_record()
internal::envelope::decode_protected_record()
internal::envelope::validate_envelope_size()
internal::envelope::validate_route_tag()
```

### Payload / attachment internals

```rust
internal::payload::pack_message()
internal::payload::unpack_message()
internal::payload::pack_attachment()
internal::payload::unpack_attachment()
internal::payload::chunk_payload()
internal::payload::reassemble_payload()
internal::payload::compress_payload()
internal::payload::decompress_payload()
internal::payload::hash_payload()
internal::payload::verify_payload_hash()
```

### Contact internals

```rust
internal::contacts::encode_contact_card()
internal::contacts::decode_contact_card()
internal::contacts::validate_contact_card()
internal::contacts::compute_safety_code()
internal::contacts::verify_safety_code()
internal::contacts::store_contact()
internal::contacts::load_contact()
internal::contacts::delete_contact()
```

### Identity vault internals

```rust
internal::identity::create_vault_record()
internal::identity::encrypt_identity()
internal::identity::decrypt_identity()
internal::identity::import_vault_record()
internal::identity::export_vault_record()
internal::identity::unlock_to_memory()
internal::identity::lock_from_memory()
internal::identity::check_password()
internal::identity::change_password()
```

### Storage internals

```rust
internal::storage::open_store()
internal::storage::migrate_store()
internal::storage::write_record()
internal::storage::read_record()
internal::storage::delete_record()
internal::storage::list_records()
internal::storage::write_checkpoint()
internal::storage::verify_checkpoint()
internal::storage::rollback_check()
internal::storage::export_backup_blob()
internal::storage::import_backup_blob()
internal::storage::storage_status()
```

### Group / lobby internals

```rust
internal::group::create_group_state()
internal::group::apply_group_policy()
internal::group::encode_lobby_invite()
internal::group::decode_lobby_invite()
internal::group::add_member()
internal::group::remove_member()
internal::group::rotate_group_key()
internal::group::derive_group_message_key()
internal::group::encrypt_group_message()
internal::group::decrypt_group_message()
```

### Benchmark internals

```rust
internal::bench::run_handshake_bench()
internal::bench::run_message_bench()
internal::bench::run_storage_bench()
internal::bench::format_report()
```

## 12. Mental model

Public API:

```text
open, identity, contacts, handshake, send, receive, lobby, backup, storage status, benchmark
```

Internal implementation:

```text
crypto, ratchets, sessions, envelopes, padding, chunks, storage, vaults, group keys
```

The app developer should never need to see chunks, padding classes, suite selection, protocol details, checkpoint verification, lobby state import/export, or advanced configuration.

## 10. JavaScript / WASM facade

The WASM binding mirrors the same simple API shape from `crates/hydra-msg-wasm`.

```javascript
import init, { WasmHydra, WasmHydraMessage } from './pkg/hydra_msg_wasm.js';

await init();

const hydra = WasmHydra.openDefault();
const id = hydra.generateId('password');
await hydra.setActiveId(id, 'password');

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

The JS/WASM API must not expose advanced protocol controls. Browser persistence in P6 is in-memory unless the app uses explicit backup/export/import helpers. See `docs/impl/wasm-javascript-bindings.md`.
