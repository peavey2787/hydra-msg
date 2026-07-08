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
- Validation is still owned by `qa/ci/check-all.*` and `qa/ci/check-examples.*`.

## Findings and changes made

### 1. WASM-only dead-code warning

The native filesystem state helper was compiled into the WASM build even though only the native path uses it. This caused a dead-code warning while building the WASM binding.

Fix applied:

- gated the native state file constant behind `cfg(not(target_arch = "wasm32"))`;
- gated the native `state_path` helper behind the same target condition.

### 2. Facade file size and separation of concerns

`crates/hydra-msg/src/lib.rs` had grown into a mixed file containing public facade types, public facade methods, persistence encoding, contact-card encoding, backup encoding, handshake encoding, payload packing, line escaping, and byte helpers.

Fix applied:

- added `crates/hydra-msg/src/codec.rs`;
- moved private encoding, decoding, persistence-line, contact-card, backup, handshake, payload, hex, byte-reader, and random-byte helpers into `codec.rs`;
- kept the public developer surface and `Hydra` facade methods in `lib.rs`;
- kept all moved helpers private to the crate module boundary;
- kept the public API unchanged.

Result:

```text
crates/hydra-msg/src/lib.rs    public facade and high-level behavior
crates/hydra-msg/src/codec.rs  private wire/storage/payload helper code
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

- `qa/ci/check-all.*` must pass;
- `qa/ci/check-examples.*` must pass;
- browser/mobile WASM packages must build;
- the WebRTC manual carrier host needs a browser smoke test;
- benchmark notes should be updated if current results materially differ;
- independent cryptographic review and interop review remain outside this local cleanup pass.

## Audit conclusion

This pass fixed the reported WASM dead-code warning and split the largest public facade source file by concern without changing the public developer API.

The codebase is cleaner and closer to the project rules, but it is not release-ready until the maintainer-run P13 validation gate passes and the external review gaps are addressed.
