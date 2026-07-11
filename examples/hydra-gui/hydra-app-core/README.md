# hydra-app-core

## Navigation

- [Main README](../../../README.md)
- [How HYDRA messaging works](../../../docs/impl/message-flow/README.md)
- [Spec docs and repo structure](../../../docs/spec/README.md)
- [Crates](../../../crates/README.md)
- [Examples](../../README.md)
- [Public developer API](../../../docs/spec/public-developer-api.md)
- [Benchmark notes](../../../docs/validation/benchmark-results.md)

Thin production reference-app orchestration over `hydra-msg`.

This crate intentionally contains no custom identity vault, contact trust format, protocol session, group state machine, message database, attachment crypto, recovery format, or rollback history. All of those operations delegate to the public SDK.

Integration tests cover first-run identity creation, identity import and switching, session-scoped unlock preferences, contact-card flows, handshakes, opaque packet send/receive, lobby flows, backup verification/import, state-password rotation, and misuse after locking or deletion.
