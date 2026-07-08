# HYDRA-MSG app architecture modularization

Status: P1 completion note.

This document records the P1 GUI refactor that split the prior monolithic
`examples/hydra-app/src/gui.rs` implementation into single-responsibility modules
without changing GUI routes, CLI routing, protocol behavior, or app-domain
behavior.

## Source ownership after P1

```text
examples/hydra-app/src/gui/
├── mod.rs              # GUI module root and GUI-focused tests
├── server.rs           # loopback server startup, bind parsing, connection handling
├── security.rs         # GUI token, Host/Origin/Referer checks, constant-time token check
├── router.rs           # HTTP method/path dispatch only
├── handlers/           # API handlers split by production app domain
├── http.rs             # minimal HTTP request/response parsing and response headers
├── forms.rs            # form decoding and required-field helpers
├── encoding.rs         # JSON escaping and hex encoding helpers
├── state.rs            # app state aggregation helpers for `/api/state`
├── html.rs             # HTML template rendering/token injection
├── assets.rs           # compile-time asset ownership
└── assets/
    ├── index.html      # browser shell markup
    ├── app.css         # GUI styling
    └── app.js          # browser-side behavior
```

## Preserved behavior

P1 preserves the existing public GUI entrypoint:

```text
cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui
```

The CLI still routes `gui` through:

```text
examples/hydra-app/src/main.rs
→ cli::run()
→ gui::run(&args[1..])
```

Existing GUI routes remain unchanged:

```text
GET  /
GET  /index.html
GET  /app.css
GET  /app.js
GET  /api/state
POST /api/config/set
POST /api/contacts/add
```

Existing local GUI security behavior is preserved:

- loopback bind remains the default;
- non-loopback bind still requires `--dangerous-allow-remote`;
- `/api/*` still requires the per-process GUI token;
- POST routes still pass Origin/Referer validation;
- Host validation remains centralized;
- request timeouts and size caps remain in server/HTTP code;
- response security headers remain emitted by `http.rs`.

## Separation of concerns

P1 intentionally keeps protocol and app-domain logic out of GUI modules.

- GUI routing lives in `router.rs`.
- HTTP parsing and response headers live in `http.rs`.
- Security checks live in `security.rs`.
- API handlers live in `handlers.rs` and call existing config/contact/app
  services.
- App-state aggregation lives in `state.rs`.
- Static frontend content is compile-time included from `gui/assets/`.

The GUI still contains demo-oriented routes and dashboard content because P1 is a
behavior-preserving refactor. Those flows remain classified for later isolation
or replacement under P6/P8/P12.

## Boundary invariant audit

P1 does not introduce new protocol constants, counters, cryptographic bounds,
storage versions, or rejection thresholds. Existing GUI boundary values remain
unchanged:

- default bind: `127.0.0.1:8787`;
- request timeout: five seconds;
- maximum HTTP header bytes: 64 KiB;
- maximum HTTP body bytes: 1 MiB;
- GUI session token: 32 random bytes encoded as 64 lowercase hex characters.

Existing tests continue to cover the most important GUI helper boundaries:

- default bind address;
- dangerous remote bind flag parsing;
- static route Host-only access;
- API token rejection and acceptance;
- cross-site POST Origin rejection;
- token injection in the index page;
- generated token length and hex encoding;
- form percent decoding.

## Next architecture risks

The next production milestones should avoid reintroducing monolithic behavior:

- P2 identity-vault UI should put shared identity logic in `hydra-app-core`, not
  in GUI handlers.
- P3 lock/unlock state should be non-UI app-domain state with GUI and CLI
  frontends.
- P4 QR/join-code bootstrap should keep payload parsing and validation outside
  frontend JavaScript.
- P12 removed the remaining reachable app demo route/control
  instead of deleting the only complete local app exercise path prematurely.
