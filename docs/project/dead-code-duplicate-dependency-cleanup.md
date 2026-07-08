# P12 Dead-code, duplicate-code, dependency, and file-size cleanup

Status: completed production-app cleanup pass.

P12 removes baggage before production QA/release-candidate work. It does not change HYDRA protocol semantics, wire formats, cryptographic constants, contact trust rules, storage encryption, rollback policy, GUI security policy, or relay/server scope.

## Source-of-truth cleanup

Active workspace crates are now exactly the crates listed in the root `Cargo.toml` workspace members:

```text
hydra-core
hydra-crypto
hydra-envelope
hydra-session
hydra-group
hydra-app-core
hydra-app
```

The previous excluded scaffold crate directories were removed from the production branch:

```text
crates/hydra-memory
crates/hydra-tests
crates/hydra-transport
```

Those names may be reintroduced later only by an explicit roadmap milestone that gives them real responsibilities, admits them to the workspace, and validates them with tests.

## Demo/dead path cleanup

P12 removed the reachable app demo harness and local demo node surface:

```text
examples/hydra-app/src/client.rs
examples/hydra-app/src/node.rs
hydra-app demo
hydra-app node
POST /api/demo/run
GUI “Run verified demo flow” control
```

The default CLI command now prints help instead of running a demo flow. The default app data directory is now `./hydra-msg-data` instead of `./hydra-demo-data`.

## Module-size cleanup

P12 split production app monoliths into single-responsibility modules:

- `examples/hydra-app/src/cli.rs` became `examples/hydra-app/src/cli/` command modules.
- `examples/hydra-app/src/services.rs` became `examples/hydra-app/src/services/` app-service modules.
- `examples/hydra-app/src/gui/handlers.rs` became `examples/hydra-app/src/gui/handlers/` API-domain modules.
- GUI JSON rendering helpers were split under `examples/hydra-app/src/gui/handlers/json/`.
- GUI JavaScript was split into small static asset files and concatenated by `assets.rs` for the existing `/app.js` route.
- GUI HTML was split into small static asset fragments and concatenated by `assets.rs` for the existing `/` and `/index.html` routes.
- GUI tests moved from `gui/mod.rs` into `gui/tests.rs`.

The active `hydra-app` frontend/orchestration files now fit the project’s 200–300 line target. Larger protocol and `hydra-app-core` implementation files remain behavior-sensitive and should be split only in a dedicated refactor with local Cargo validation.

## Dependency cleanup

P12 removed direct `hydra-app` dependencies that were only needed by the deleted demo harness:

```text
hydra-core
hydra-group
```

`hydra-app` now depends directly only on the frontend/app dependencies it uses:

```text
getrandom
hydra-app-core
hydra-crypto
rand_core
```

## Authority boundaries after P12

- Protocol constants and shared discriminants remain owned by `hydra-core`.
- Envelope wire logic remains owned by `hydra-envelope`.
- Protocol/session/group behavior remains owned by protocol crates.
- App-domain state, vault, contact, storage, recovery, and chat-shell logic remain owned by `hydra-app-core`.
- CLI and GUI are frontends over shared services in `hydra-app`.
- GUI handlers own HTTP/API presentation only; they do not define protocol behavior.
- Static GUI assets own browser presentation only; they do not define app-domain state machines.

## Checks performed in this environment

The environment used for this edit does not have Cargo installed, so Rust compilation, tests, and Clippy must still be run locally.

Checks performed here:

```text
node --check on the concatenated GUI JavaScript bundle
grep for todo!/unimplemented!/TODO/FIXME in crates/
grep for stale demo/deprecated markers in crates/
line-count audit for hydra-app frontend/orchestration files
```
