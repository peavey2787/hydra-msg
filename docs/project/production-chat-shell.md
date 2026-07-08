# Production chat shell and message UX

Status: P6 implementation note.

P6 replaces the hardcoded demo chat and group surfaces with a production chat workflow shell backed by shared app-domain code and encrypted local storage.

## Source ownership

- `hydra-app-core::ChatShell` owns chat-shell app-domain behavior over the encrypted `MessageStore`.
- `examples/hydra-app/src/gui/handlers.rs` exposes local GUI API handlers that call `ChatShell`.
- `examples/hydra-app/src/gui/assets/index.html` defines the mobile-first chat, group, and developer/test UI surfaces.
- `examples/hydra-app/src/gui/assets/app.js` renders chat state and submits local chat actions.
- Protocol semantics, ratchets, wire formats, and crypto rules remain outside GUI code.

## Implemented workflow

The GUI now supports:

- a chat list sourced from the encrypted message database;
- an empty state that guides the user to trust a contact, unlock the active identity, and start a chat;
- creating or opening a direct chat from an already trusted contact;
- creating local group chat shells for Lite, Interactive, and Broadcast modes;
- selecting a chat and rendering its stored message thread;
- storing outbound messages through shared app-domain logic;
- storing reviewed inbound messages through an Advanced-only local review form.

The previous hardcoded `direct hello from Alice` and `Lite group demo` chat surfaces were removed from normal chat/group screens.

## Developer/test isolation

P12 removed the remaining reachable app demo route/control from the production app path.

## Security boundaries

P6 does not add a production relay, mailbox server, or plaintext transport.

Messages entered in the GUI are stored only in the encrypted local message database. The reviewed inbound-message form exists to exercise the local message UX and storage path; it does not claim to download, decrypt, or accept relay-delivered HYDRA envelopes.

Chat actions require the active identity to be unlocked in the memory-only session cache. Passwords are not stored and are not added to URLs.

## Metadata boundary

The GUI renders only local chat metadata required for the user experience:

- conversation kind;
- epoch/state counters;
- message count;
- sender fingerprint prefix;
- message index;
- local received/stored timestamp.

No server-side plaintext behavior or relay metadata model is introduced by this milestone.

## Boundary invariant audit

P6 adds and checks the following boundaries:

- message body must be non-empty;
- local plaintext body accepted by the chat shell is bounded to 64 KiB;
- conversation IDs must decode to exactly 32 bytes;
- sender IDs must decode to exactly 32 bytes;
- group chat shell creation rejects `direct` as a group kind;
- direct chat creation requires a trusted contact fingerprint;
- chat actions reject use when the active identity is not unlocked;
- reviewed inbound messages require either an explicit sender fingerprint or a direct contact member.

## Non-goals

P6 does not implement:

- production network transport;
- offline relay/mailbox behavior;
- server-side message queues;
- plaintext attachment transport;
- full chat synchronization between devices;
- a recovery override for rollback warnings.

Those remain later roadmap concerns.
