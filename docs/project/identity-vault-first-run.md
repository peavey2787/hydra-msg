# P2 Identity vault and first-run setup

Status: production app milestone documentation.

P2 makes identity setup the first production GUI flow without changing HYDRA protocol semantics.

## Source-of-truth ownership

- `hydra-app-core::IdentityVault` owns multi-identity registry behavior.
- `hydra-app-core::IdentityStore` owns encrypted-at-rest private identity storage.
- `hydra-app` GUI owns first-run presentation, form submission, and local API routing.
- The GUI does not own protocol constants, private-key encoding, or identity cryptography.

## First-run rule

The GUI calls `/api/state` on load. If the production identity vault contains no identities, the GUI shows the first-run setup screen and hides the normal app shell.

The normal app shell is shown only after at least one production identity exists in the vault.


## Identity vault model

The vault stores public metadata in:

```text
<data-dir>/identities/identity-vault.txt
```

Each private identity is stored in a separate encrypted identity database:

```text
<data-dir>/identities/<identity-id>.identity.db
```

The registry contains only public metadata:

- local vault identity id;
- label;
- identity-store filename;
- identity fingerprint;
- device id;
- device fingerprint;
- generation;
- revoked flag;
- active id.

Private identity seed material remains inside `IdentityStore` ciphertext and is never written to the registry.

## Supported P2 flows

P2 supports:

1. Generate new encrypted identity.
2. Import an existing encrypted identity-store file.
3. Import an encrypted recovery backup.
4. Store multiple identities in the same vault registry.
5. Show public identity summaries in GUI state.

P2 does not yet implement session unlock, identity switching, lock-all, or idle-timeout behavior. Those are P3 responsibilities.

## Password handling

Passwords are accepted only through POST form bodies sent to the local loopback GUI API.

Passwords are used to derive encryption keys for identity storage or backup import and are not stored in:

- vault registry;
- GUI state JSON;
- URLs or query strings;
- config files;
- frontend JavaScript state beyond the form submission lifetime.

The GUI never returns private identity seed material.

## Import safety

Importing an existing identity-store file decrypts the source with the source password and re-encrypts it into the vault with the new password.

By default, imported identity-store files become a new device identity record rather than silently preserving the source device id.

Preserving a device id is exposed only as an Advanced import option.

Importing encrypted recovery backups uses the existing recovery policy. Preserving a source device id is allowed only when the backup policy permits it.

## Boundary invariant audit

P2 introduced or used these boundary values:

- identity label length: 1 through 64 bytes accepted; empty, tab, CR/LF, and overlong labels rejected;
- identity id length: exactly 64 hexadecimal characters;
- identity filename: exactly `<64-hex-id>.identity.db`;
- password length: empty rejected, non-empty accepted;
- registry record field count: exactly 8 tab-separated fields;
- first-run state: zero vault identities shows setup, one or more vault identities shows app shell.

The non-UI app-domain tests cover multiple identities, registry reload, wrong-password rejection, imported identity-store files, corrupted identity file rejection, and password non-disclosure in the registry.

## Intentional non-goals for P2

P2 intentionally does not add:

- production remote relay/mailbox behavior;
- QR/join-code bootstrap;
- contact safety-number UX changes;
- identity lock/unlock session cache;
- idle timeout;
- complete chat-message UX;
- final production release claims.
