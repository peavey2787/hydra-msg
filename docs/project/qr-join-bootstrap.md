# QR-code and join-code bootstrap

Status: P4 implementation note.

This document records the production-app bootstrap boundary added for P4.

## Source of truth

- App-domain bootstrap payload logic lives in `hydra-app-core::chat_bootstrap`.
- GUI handlers only create, validate, display, and review bootstrap payloads.
- GUI code does not define cryptographic protocol semantics or private-key handling.

## Public payload model

The QR payload and join code are the same string format:

```text
hydra-msg-chat-v1|...
```

The payload contains public bootstrap data only:

- inviter label;
- ML-DSA public identity key;
- identity fingerprint;
- device id;
- device fingerprint;
- mailbox hint;
- optional recipient fingerprint;
- created/expires timestamps;
- context-binding hash;
- safety number.

The payload must not contain private keys, passwords, plaintext messages, ratchet
state, group secrets, or decrypted identity material.

## Context binding

Each payload includes a domain-separated context-binding hash over the public
fields. This does not replace later contact trust or safety confirmation. It
prevents malformed or internally inconsistent bootstrap strings from being
accepted as valid review material.

Recipient-bound invites include the intended recipient identity fingerprint in
that context. A recipient-bound invite is rejected when the active local identity
fingerprint does not match.

## Expiration boundaries

Invite TTL is explicit:

- minimum: 60 seconds;
- default: 86400 seconds;
- maximum: 2592000 seconds.

Boundary behavior:

- `N = 60` succeeds;
- `N = 59` is rejected;
- `N = 2592000` succeeds;
- `N = 2592001` is rejected;
- an invite is valid before `expires_at_ms`;
- an invite is expired at `now_ms >= expires_at_ms`.

## GUI behavior

The GUI adds a Start Chat flow:

- create a QR-ready payload / join code from the active unlocked identity;
- copy the join code;
- paste or scan/import a join code for review;
- show safety number, fingerprint, mailbox hint, and advanced public details
  before trust is accepted.

Trust is not silently accepted in P4. P5 owns contact trust and safety
verification UX.

## Non-goals

P4 does not add:

- a production relay/server/mailbox;
- plaintext attachment transfer;
- automatic contact trust;
- protocol-level handshake changes;
- private-key export in bootstrap payloads.
