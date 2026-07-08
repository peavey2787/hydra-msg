# CLI/GUI shared app services

Status: P9 implementation note.

P9 keeps the CLI and local browser GUI as separate frontends over shared app behavior. The production rule is that CLI and GUI may format output differently, but they should not own separate identity, contact, backup, recovery, or chat state machines.

## Source ownership

```text
examples/hydra-app-core/      app-domain primitives and persistent stores
examples/hydra-app/src/services.rs  shared app-service orchestration
examples/hydra-app/src/cli.rs       CLI argument parsing and terminal formatting
examples/hydra-app/src/gui/         local browser GUI routing, forms, JSON, and assets
```

`hydra-app-core` remains the owner for reusable domain state: identity vault, contact trust store, message store, chat shell, recovery backup, signed backup history, and bootstrap payload validation.

`examples/hydra-app/src/services.rs` is the shared frontend service layer for production app actions that need local `AppConfig`, data directory ownership, and the app storage secret. It coordinates app-core stores so CLI and GUI do not each reimplement the same behavior.

## Shared service coverage

The shared service layer now covers:

- config mutation helper;
- identity list/generate/import/switch;
- active identity public-material loading for CLI commands;
- contact list/add/review/trust/QR verification;
- QR/join-code bootstrap creation and review;
- chat snapshot, direct chat creation, group chat creation, outbound send, and reviewed inbound storage;
- storage/recovery status;
- encrypted recovery-backup export/inspection;
- signed checkpoint export;
- signed backup-history checking.

The GUI contact and identity routes now use the shared service layer where practical. Existing GUI recovery/chat routes still format JSON locally, but the shared service layer owns equivalent CLI flows and should be the target for further extraction when P12 cleanup removes remaining duplicate frontend orchestration.

## CLI parity

The CLI help now documents production app flows, including:

- identity setup and switching;
- contact review/trust/QR verification;
- QR/join-code bootstrap creation and review;
- chat list/direct/group/send/reviewed-inbound flows;
- encrypted recovery-backup export/inspection;
- signed checkpoint export and rollback-history checks;
- local GUI launch and dangerous remote-bind warning.

The CLI does not persist an unlock-once app session across invocations because each CLI command is a separate process. CLI commands that need private identity material take the identity password for that command only.

## Security boundaries

- Passwords are accepted as CLI arguments only for explicit command-line flows; they are not stored by the service layer.
- GUI passwords remain POST-body only, not URLs.
- CLI and GUI both use encrypted app-core stores.
- Contact key changes require explicit acceptance.
- Recovery backup active-device cloning remains explicit and off by default.
- No production relay/server/mailbox behavior was added.

## Boundary audit

P9 introduced a shared frontend service boundary. The boundary is intentionally app-layer only: it may load `AppConfig`, open the app data directory, load the app storage secret, and call app-core APIs. It must not define protocol constants, wire formats, cryptographic semantics, ratchet behavior, group protocol rules, or trust policy independent of app-core.

A P9 action is complete only when CLI and GUI call either app-core directly or the shared service layer; they must not each carry independent copies of identity-vault, contact-trust, recovery, or chat state-machine logic.
