# Repository structure

## Navigation

- [Main README](../../README.md)
- [Spec document index](#spec-document-index)
- [Protocol spec](protocol-spec.md)
- [Threat model](threat-model.md)
- [Security proof sketch](security-proof-sketch.md)
- [State machines](state-machines.md)
- [Envelope serialization](envelope-serialization.md)
- [Chain-key evolution](chain-key-evolution.md)
- [TreeKEM profile](tree-kem.md)
- [Group modes](group-modes.md)
- [Group rekey](group-rekey.md)
- [Anonymous authorization](anonymous-authorization.md)
- [Canonical encrypted local snapshot persistence](canonical-snapshot-persistence.md)

This document is the project structure map. It explains where files belong so the repository stays organized, consistent, and easy to maintain.

## Spec document index

The persistence contract is specified in [Canonical encrypted local snapshot persistence](canonical-snapshot-persistence.md).

The Navigation section above is the canonical spec-side index for protocol specs and repository structure. Public API entry points stay on the main README navigation.

## Top-level layout

```text
crates/      maintained Rust components and system modules
docs/        specifications, implementation notes, validation notes, and future-work notes
qa/          local correctness scripts, fixtures, vectors, fuzzing, release evidence, and validation tools
examples/    runnable examples and small demo entry points
external/    third-party apps, libraries, or vendored external material when needed
scripts/     automation that is not part of QA
```

Public product documentation belongs in one of the grouped docs folders below. Maintainer-only planning material is kept out of public navigation.

## `crates/`

`crates/` holds the maintained code components. Each crate should have one clear responsibility and should avoid duplicating logic owned by another crate.

Current app-facing components include:

```text
crates/hydra-msg       Rust SDK facade for app developers
crates/hydra-msg-wasm  WASM/JavaScript binding over the facade
crates/hydra-msg-cli   command-line developer utility over the facade
```

Lower-level protocol crates live beside them and should stay focused on their own domain: crypto, sessions, groups, serialization, and shared core types.

## `hydra-group` ownership notes

`crates/hydra-group` owns group membership, group state, group messages, commit transitions, canonical group encodings, group validation, and group test-vector behavior. The active SRP split keeps high-churn protocol mechanics in focused module folders instead of mixed-concern monoliths:

```text
crates/hydra-group/src/canonical/  canonical encodings, validation helpers, hashes, and confirmation tags by encoding family
crates/hydra-group/src/state/      live group state, private membership state, sender chains, replay state, snapshots, and roster views
crates/hydra-group/src/commit/    commit preparation, validation, transition, payload, key-schedule, tree-update, application, and install flow
```

New Rust source files should usually stay under 400 lines. Any file that must exceed that threshold needs a documented exception in `qa/ci/policy/rust-size-allowlist.txt`, including a max line ceiling and a specific ownership reason. This is a drift guard, not a substitute for SRP: remove allow-list entries when a file is split below the threshold.


## `hydra-msg` facade ownership notes

`crates/hydra-msg` is the app-developer facade. Its root `lib.rs` keeps the public API surface and re-exports stable, while focused private modules own the implementation details:

```text
crates/hydra-msg/src/api/identity.rs    identity ids, summaries, encrypted identity records, and identity lifecycle methods
crates/hydra-msg/src/api/contacts.rs    contact ids, contact metadata, contact cards, import/export, verification, and blocking
crates/hydra-msg/src/handshake/mod.rs   signed hybrid handshake orchestration, session status, session records, and contact payload sealing/opening
crates/hydra-msg/src/messages/mod.rs    message ids, attachments, message builders, received messages, and message persistence helpers
crates/hydra-msg/src/api/lobbies.rs     lobby ids, lobby policy, invites, member management, and per-member lobby sends
crates/hydra-msg/src/api/storage.rs     local open/persist/load behavior, backups, snapshots, and storage status
crates/hydra-msg/src/api/benchmark.rs   facade benchmark surface
crates/hydra-msg/src/codec/         private wire/state/contact/message/lobby/handshake encoding helpers by domain
```

The public API remains available through the crate root; the modules are implementation ownership boundaries, not new public paths.

## `docs/`

`docs/` is split by purpose:

```text
docs/impl/         implementation-focused docs and scaffolding
docs/spec/         foundational specifications and public behavior contracts
docs/validation/   organized validation gates, evidence, benchmarks, and release governance
```

Important product docs and release evidence must not live in assistant working-note folders. Use `docs/validation/benchmarks/` for measurements, `docs/validation/evidence/` for audit records, `docs/validation/gates/` for gate descriptions, and `docs/validation/release/` for release governance.

## `qa/`

`qa/` owns correctness-related tooling:

```text
qa/ci/        local CI scripts and one-command check gates
qa/fuzz/      fuzzing harnesses
qa/tools/     internal QA utilities
qa/vectors/   protocol fixtures and test vectors
qa/tests/     global or system-level tests when needed
```

The master local validation command lives in `qa/ci/`.

## `examples/`

`examples/` holds runnable examples and minimal demo programs. Examples should show how to use the public SDK without becoming product architecture.

## `external/`

`external/` is reserved for third-party apps, libraries, or vendored outside material when needed.

## `scripts/`

`scripts/` is for automation that is not itself QA: environment setup, local developer bootstrap, packaging helpers, or repeatable maintenance commands.

## General rules

```text
Keep file and folder ownership clear.
Keep naming consistent.
Keep each module focused on one responsibility.
Avoid duplicated or unused code.
When a file grows too large, split it by responsibility.
When a folder gathers too many files, group them by purpose.
Before calling work complete, ask whether it is production-ready, enterprise-grade, and mathematically sound. If not, document what is missing.
```
