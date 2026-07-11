# HYDRA-MSG CLI developer tool

## Navigation

- [Main README](../../README.md)
- [How HYDRA messaging works](message-flow/README.md)
- [Spec docs and repo structure](../spec/README.md)
- [Crates](../../crates/README.md)
- [Examples](../../examples/README.md)
- [Public developer API](../spec/public-developer-api.md)
- [Benchmark notes](../validation/benchmark-results.md)

Status: developer utility over the public `hydra-msg` facade.

`hydra-msg-cli` is a thin command-line helper for trying the simple
facade API from a terminal. It is not protocol authority and it does not add any
advanced public API. Every command is intentionally a wrapper around the public
`hydra-msg` facade.

## Commands

```text
hydra-msg-cli generate-id <data-dir> <password>
hydra-msg-cli contact-card <data-dir> <identity-id-hex> <password>
hydra-msg-cli handshake-demo [data-dir]
hydra-msg-cli send-demo [data-dir] [message]
hydra-msg-cli attachment-demo [data-dir]
hydra-msg-cli bench [data-dir]
hydra-msg-cli doctor [data-dir]
```

## Cargo examples

```bash
cargo run -p hydra-msg-cli -- generate-id ./hydra-msg-data password
cargo run -p hydra-msg-cli -- contact-card ./hydra-msg-data <id-hex> password
cargo run -p hydra-msg-cli -- handshake-demo ./hydra-msg-cli-demo
cargo run -p hydra-msg-cli -- send-demo ./hydra-msg-cli-demo "hello"
cargo run -p hydra-msg-cli -- attachment-demo ./hydra-msg-cli-demo
cargo run -p hydra-msg-cli -- bench ./hydra-msg-data
cargo run -p hydra-msg-cli -- doctor ./hydra-msg-data
```

## Ownership rules

- The CLI depends on `hydra-msg`; lower-level crates must not depend on the CLI.
- The CLI must not expose protocol internals, suite selection, public builders,
  public config profiles, session export/import, chunks, checkpoints,
  predicates, or AOL2 state.
- Demo commands may create throwaway local data directories, but runtime data
  must remain ignored by git.
- Long-term, this crate may be renamed or paired with a `cargo-hydra-msg`
  binary if a Cargo subcommand is desired.
