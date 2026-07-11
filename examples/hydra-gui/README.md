# HYDRA production reference GUI

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../docs/spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../README.md)
- [Public developer API](../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../docs/validation/benchmarks/benchmark-results.md)

`hydra-gui/` contains the current public-SDK reference application:

- `hydra-app-core`: thin UX/state orchestration over `hydra-msg`.
- `hydra-app`: CLI and loopback-only local web GUI using `hydra-app-core`.

## Ownership boundary

`hydra-msg` owns identities, contact trust, sessions, replay state, direct and lobby message cryptography, attachments, encrypted state, and backups.

`hydra-app-core` owns only process-local UX metadata: selected profile/conversation, drafts, remember-for-session preference, notification preferences, carrier configuration, and transient display history. It has one dependency: `hydra-msg`.

`hydra-app` treats every handshake, direct-message, and lobby payload as opaque bytes. File paths, HTTP forms, WebRTC, relays, or another carrier may move those bytes without interpreting them.

## CLI

```bash
cargo run --manifest-path examples/hydra-gui/hydra-app/Cargo.toml -- \
  --data-dir ./hydra-data \
  --state-password 'state password' \
  identity generate Primary 'identity password'
```

Run `help` for the complete command model. The command groups are:

- `identity generate/list/switch/unlock/lock/export/import/change-password/delete`
- `contacts my-card/preview/add/verify/export/import`
- `handshake offer/answer/finish`
- `messages send/receive`
- `lobbies create/add-member/invite/join/send/receive/leave`
- `backup export/verify/import/change-state-password/status`
- `storage status/debug-status`

## Local GUI

```bash
cargo run --manifest-path examples/hydra-gui/hydra-app/Cargo.toml -- \
  --data-dir ./hydra-data \
  --state-password 'state password' \
  gui 127.0.0.1:8787
```

The server refuses non-loopback binds. Mutating routes require a same-origin custom request header and reject foreign browser origins.

## Validation

```bash
cargo test --manifest-path examples/hydra-gui/hydra-app-core/Cargo.toml
cargo check --manifest-path examples/hydra-gui/hydra-app/Cargo.toml --all-targets
cargo test --manifest-path examples/hydra-gui/hydra-app/Cargo.toml
```
