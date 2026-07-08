# HYDRA-MSG source hygiene audit

Status: current cleanup audit after the P13 script-prep fixes.

This pass checked the repository against the project-specific rules in `docs/roadmap.md`, `crates/README.md`, `examples/README.md`, and `docs/spec/public-developer-api.md`.

## Rules checked

- Active protocol and product code stays under `crates/`.
- Runnable app-developer examples stay under `examples/`.
- `hydra-msg` remains the public developer facade.
- Carrier code stays above the facade and only moves opaque HYDRA bytes.
- Lower-level crates do not depend on the facade, CLI, WASM binding, or examples.
- Runtime data and identity material stay out of git.
- Public API scope stays trimmed: no config/profile/builder layer, no protocol-info surface, no session import/export surface, no public chunk surface, no checkpoint surface, no predicate surface, and no lobby-state import/export surface.
- Source files should stay organized by concern, with large mixed-concern files split as soon as they start hiding separate responsibilities.
- Validation is owned by the tiered `qa/ci/check-all.*` runner, with `qa/ci/check-tests.*` and `qa/ci/check-examples.*` as the two lower-level gates.

## Findings and changes made

### 1. WASM-only dead-code warning

The native filesystem state helper was compiled into the WASM build even though only the native path uses it. This caused a dead-code warning while building the WASM binding.

Fix applied:

- gated the native state file constant behind `cfg(not(target_arch = "wasm32"))`;
- gated the native `state_path` helper behind the same target condition.

### 2. Facade file size and separation of concerns

`crates/hydra-msg/src/lib.rs` and the former private `codec.rs` had grown into mixed files containing public facade types, high-level facade methods, persistence encoding, contact-card encoding, backup encoding, handshake encoding, payload packing, line escaping, byte helpers, lobby helpers, and benchmark behavior.

Fix applied:

- kept the public developer API re-exported through `crates/hydra-msg/src/lib.rs`;
- moved identity lifecycle code into `identity.rs`;
- moved contact-card and contact-book code into `contacts.rs`;
- moved handshake/session code into `handshake.rs`;
- moved message and attachment code into `messages.rs`;
- moved lobby invite/member/send code into `lobbies.rs`;
- moved local state, backup, and persistence code into `storage.rs`;
- moved benchmark behavior into `benchmark.rs`;
- replaced the single large `codec.rs` with a private `codec/` module tree split by domain;
- extended the source-size guardrail to scan both `crates/hydra-group/src` and `crates/hydra-msg/src`;
- kept all moved helpers private to crate/module boundaries;
- kept the public API unchanged.

Result:

```text
crates/hydra-msg/src/lib.rs       public facade surface and stable re-exports
crates/hydra-msg/src/identity.rs  identity ids, records, import/export, active identity, and unlock flow
crates/hydra-msg/src/contacts.rs  contact ids, contact cards, verification, blocking, and import/export
crates/hydra-msg/src/handshake.rs handshake wrappers, session records, and opaque payload sealing/opening
crates/hydra-msg/src/messages.rs  message ids, attachments, sent/received messages, and message store helpers
crates/hydra-msg/src/lobbies.rs   lobby ids, policy, invites, members, and per-member sends
crates/hydra-msg/src/storage.rs   open/load/persist, snapshots, backups, and storage status
crates/hydra-msg/src/benchmark.rs facade benchmark report
crates/hydra-msg/src/codec/       private wire/state/contact/message/lobby encoding helpers
```

### 3. Crate and example ownership

The active workspace remains aligned with the ownership rules:

- protocol/product crates are under `crates/`;
- examples are under `examples/`;
- demo reference material remains outside the active workspace;
- WebRTC and file examples remain carriers only;
- `hydra-msg` does not depend on example crates.

### 4. Runtime data and local state

No runtime `hydra-msg-data/` directory is present in the package tree. The root `.gitignore` still excludes local HYDRA runtime data.

### 5. Remaining release blockers

The repository is not ready for a release tag until P13 is clean on a real developer machine.

Still required:

- `qa/ci/check-all.*` must pass, including the lower-level tests and examples gates;
- browser/mobile WASM packages must build;
- the WebRTC manual carrier host needs a browser smoke test;
- benchmark notes should be updated if current results materially differ;
- independent cryptographic review and interop review remain outside this local cleanup pass.

## Audit conclusion

This pass fixed the reported WASM dead-code warning, split the public facade source by concern, split the former monolithic codec helper by domain, and kept the public developer API unchanged.

The codebase is cleaner and closer to the project rules, but it is not release-ready until the maintainer-run P13 validation gate passes and the external review gaps are addressed.
