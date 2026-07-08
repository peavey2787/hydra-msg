# Identity switching and session unlock UX

Status: P3 implementation note.

This document records the production-app boundary for multi-identity switching,
manual locking, and memory-only app-session unlock behavior.

## Source ownership

- `hydra-app-core::IdentityVault` owns encrypted-at-rest identity registry and
  active-identity selection.
- `hydra-app-core::IdentityUnlockSession` owns memory-only unlocked identity
  state for the current app process.
- `examples/hydra-app/src/gui/state.rs` owns GUI process state plumbing and mutex access.
- `examples/hydra-app/src/gui/handlers.rs` exposes local GUI API routes over the shared
  app-domain logic.
- GUI HTML/CSS/JS renders controls only; it does not own private-key, password,
  crypto, protocol, or vault semantics.

## Security model

Each identity remains encrypted at rest in its own password-protected
`IdentityStore` file. Passwords are accepted only in POST bodies and are never
stored in the vault registry, GUI state API, URLs, or logs.

When the user unlocks an identity session, the app attempts to open all
non-revoked identities that decrypt with the supplied password. Matching
identity stores are cached in process memory only. This lets a user switch among
those unlocked identities without re-entering the password.

First-run identity generation and identity import auto-unlock the created active
identity for the running app process after the password confirmation succeeds.
This fixes the public contact-card flow: a user can generate a new identity and
immediately open Contacts → Show my QR / join code without re-entering the
password.

Locking clears the memory cache by dropping the cached `IdentityStore` values.
The encrypted files remain on disk; plaintext private identity material is not
written back to disk by the unlock cache.

## UI behavior

The Security screen now supports:

- listing all vault identities;
- switching the active identity;
- unlocking matching identities for the app session;
- optional memory-only remember-me durations: session, 24 hours, 1 week,
  1 month, 1 year, forever-until-lock/app-exit, or custom seconds;
- manually locking all identities;
- showing whether the active identity is unlocked and when an absolute remember
  duration expires;
- configuring an optional idle lock timeout under Advanced.

The normal identity list remains public metadata only: label, public
fingerprint, device id, device fingerprint, generation, and revocation flag.

## Idle timeout boundary

`MAX_IDLE_TIMEOUT_SECONDS = 86400`.

- `None` or GUI value `0` disables idle auto-lock.
- `1` second is the smallest enabled timeout.
- `86400` seconds is the largest enabled timeout.
- `86401` seconds is rejected.
- When elapsed idle time is greater than or equal to the configured timeout, the
  unlocked memory cache is cleared.

## Remember-me and app-close behavior

Remember-me is memory-only. The app never stores the identity password or writes
plaintext private identity material back to disk. Absolute remember durations are
enforced by `IdentityUnlockSession` and are capped at one year for finite
durations. The **forever** option means forever inside this running app process
until the user presses **Lock all identities** or exits the app; it is not a
persistent OS keychain unlock.

Closing the `examples/hydra-app` GUI process drops `GuiAppState` and
`IdentityUnlockSession`, clearing the memory-only unlock cache.

## Non-goals

P3 does not implement persistent OS-keychain unlock, relay/mailbox
infrastructure, or native desktop credential-manager integration.
