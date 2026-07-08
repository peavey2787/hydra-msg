# GUI security hardening review

Status: P10 implementation note.

This document records the local browser GUI security boundary after P10.

## Goal

The HYDRA-MSG GUI is a local control surface for the app. It may host a local
web interface, but it must not become a production relay, mailbox, or remote
administration service.

The GUI must remain safe by default:

```text
local browser -> loopback GUI server -> shared app services -> app-core state
```

## Bind policy

Default GUI bind remains loopback only:

```text
127.0.0.1:8787
```

Non-loopback bind is refused unless the user starts the GUI with the explicit
flag:

```text
cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui --addr <ip:port> --dangerous-allow-remote
```

The browser UI does not expose a setting to enable remote binding.

## Request authorization

All `/api/*` routes require the per-process random GUI token in:

```text
X-Hydra-Gui-Token
```

The token is generated fresh for each GUI process and injected only into the
locally served HTML shell. It is not persisted as app configuration.

All POST routes pass through the shared GUI security gate before any handler is
called. Cross-site `Origin` or `Referer` values are rejected before the request
body can mutate app state.

## Host validation

Every request must have a valid `Host` header matching the listener port.

Remote `Host` names are rejected by default. Loopback hosts are accepted. Remote
hosts are accepted only when the process was started with the explicit dangerous
remote-bind flag.

## Size and timeout limits

The GUI HTTP reader enforces:

```text
MAX_HTTP_HEADER_BYTES = 64 KiB
MAX_HTTP_BODY_BYTES   = 1 MiB
```

The TCP connection handler applies read and write timeouts before parsing the
request.

P10 added explicit tests for oversized header rejection, oversized body rejection, and the bounded timeout constant used by the connection handler.

## Response headers

All GUI responses include browser hardening headers:

- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Content-Security-Policy`
- `frame-ancestors 'none'`
- `form-action 'self'`

## Secret handling boundary

`/api/state` may return public status and public summaries only.

It must not return:

- passwords;
- private identity keys;
- private identity seeds;
- decrypted identity material;
- storage secret bytes;
- ratchet secrets;
- group secrets;
- plaintext recovery-backup passwords.

Passwords are accepted only through POST bodies for the specific action that
needs them. Passwords must not be placed in URLs, stored in config, echoed in
JSON responses, or logged.

## Trust-changing routes

The following state-changing routes are protected by the common GUI security
boundary:

```text
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

P10 added a route-table test that verifies every listed POST route rejects a
missing GUI token and rejects a cross-site `Origin`.

## Manual penetration-style negative checks

Before treating the GUI as production-ready, manually check:

1. Start normally and confirm it binds to loopback only:

   ```text
   cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui
   ```

2. Confirm remote bind is rejected without the dangerous flag:

   ```text
   cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui --addr 0.0.0.0:8787
   ```

3. Confirm remote bind requires explicit warning-bearing startup:

   ```text
   cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui --addr 0.0.0.0:8787 --dangerous-allow-remote
   ```

4. Send `/api/state` without `X-Hydra-Gui-Token` and confirm `403`.

5. Send any POST route with a wrong token and confirm `403`.

6. Send any POST route with `Origin: http://evil.example` and confirm `403`.

7. Send a request with an oversized `Content-Length` and confirm it is rejected.

8. Confirm browser responses include the hardening headers listed above.

9. Create/import/unlock identities and confirm `/api/state` never contains
   password values, private keys, private seeds, or decrypted identity material.

10. Confirm passwords are not visible in URLs, browser history, logs, or JSON
    responses.

## Non-goals

P10 does not add:

- production relay or mailbox infrastructure;
- remote administration;
- TLS termination;
- account server authentication;
- internet-facing GUI support;
- protocol semantic changes.
