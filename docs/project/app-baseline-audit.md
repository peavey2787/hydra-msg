# HYDRA-MSG app baseline audit

Status: current after P12 cleanup.

## CLI entrypoint

`hydra-app` routes through:

```text
examples/hydra-app/src/main.rs
→ cli::run()
→ examples/hydra-app/src/cli/
```

Default `hydra-app` prints help. Production CLI command groups are:

```text
config
identity
contacts
bootstrap
chats
backup
recovery
gui
```

There is no production node/relay command in `hydra-app`.

## GUI entrypoint

`cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui` routes through:

```text
main.rs → cli::run() → gui::run(&args[1..])
```

The GUI is a local browser control surface. It may host the local UI, but it does not implement a production relay, mailbox, or server-side plaintext service.

## Active GUI routes

```text
GET  /
GET  /index.html
GET  /app.css
GET  /app.js
GET  /api/state
POST /api/config/set
POST /api/contacts/add
POST /api/contacts/review
POST /api/contacts/trust
POST /api/contacts/verify-qr
POST /api/bootstrap/create
POST /api/bootstrap/accept
POST /api/chats/direct
POST /api/chats/group
POST /api/chats/send
POST /api/chats/receive-review
POST /api/identity/generate
POST /api/identity/import-store
POST /api/identity/import-backup
POST /api/identity/switch
POST /api/identity/unlock-session
POST /api/identity/lock-all
POST /api/identity/idle-timeout
POST /api/recovery/export-backup
POST /api/recovery/inspect-backup
POST /api/recovery/export-checkpoint
POST /api/recovery/check-history
```

## Active workspace crates

The root workspace currently admits only active crates:

```text
hydra-core
hydra-crypto
hydra-envelope
hydra-session
hydra-group
hydra-app-core
hydra-app
```

Previous excluded scaffold crates were removed in P12 and are not production source or QA evidence.

## Source ownership

| Responsibility | Owner |
|---|---|
| Protocol constants/discriminants | `hydra-core` |
| Wire/envelope encoding | `hydra-envelope` |
| Crypto backend wrappers | `hydra-crypto` |
| Session/ratchet/refresh | `hydra-session` |
| Group/TreeKEM | `hydra-group` |
| App-domain identity/contact/chat/storage/recovery logic | `hydra-app-core` |
| CLI command parsing/output | `examples/hydra-app/src/cli/` |
| Shared CLI/GUI orchestration | `examples/hydra-app/src/services/` |
| Local browser GUI routing/security/API presentation | `examples/hydra-app/src/gui/` |
| Browser presentation assets | `examples/hydra-app/src/gui/assets/` |

## P12 cleanup status

P12 removed reachable app demo and placeholder node paths, deleted excluded scaffold crates, split production app monoliths, changed the default data directory to `./hydra-msg-data`, and updated crate ownership docs.
