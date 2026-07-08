# HYDRA-MSG P12 release-readiness cleanup

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)

Status: P12 cleanup artifact.

P12 makes the developer-facing repository credible before the maintainer-run P13 validation gate. It does not publish a release, freeze the protocol, add new public APIs, add carriers to `hydra-msg`, or run the final validation commands.

## Release status

HYDRA-MSG is currently a release-candidate worktree for the stupid-simple `hydra-msg` developer API.

Accurate status wording:

- `hydra-msg` is the public Rust SDK facade.
- `hydra-msg-wasm` mirrors the facade for browser/mobile WASM.
- `hydra-msg-cli` is a thin developer utility over the facade.
- WebRTC, files, relays, libp2p, Kaspa pointers, QR codes, HTTP, and mailboxes are carriers only.
- The protocol is not described as independently audited, finally standardized, or production frozen.
- P13 manual validation is still required before release.

## Cleanup performed

- Kept the active workspace focused on protocol/product crates and active facade examples.
- Kept demo app crates outside the active workspace under `examples/` as reference material only.
- Removed stale phase wording from demo app CSS comments.
- Added real-world benchmark notes under `docs/validation/benchmark-results.md`.
- Updated README files to point app developers at `hydra-msg` first.
- Preserved the trimmed public API rule: no config/profile/builder layer, no advanced public API, no protocol-info/suite APIs, no session import/export, no public chunk API, no checkpoint/lobby-state/predicate APIs.

## Static cleanup checks performed in this environment

The assistant environment does not have Cargo/Rust installed, so P12 used static source checks only. P13 owns actual validation through `qa/ci/check-all.*`, with `qa/ci/check-tests.*` and `qa/ci/check-examples.*` available for isolated runs.

Static checks performed:

```bash
# Check for removed out-of-scope naming/phase markers across the working tree.
# Check active crates/examples for source TODO and unimplemented markers.
```

Expected P12 result: no matches for removed out-of-scope naming/phase markers, no runtime-data artifacts, and no source TODO/unimplemented markers in active crates/examples.

## P13 handoff

P13 is manual validation. The maintainer should run `qa/ci/check-all.ps1` on Windows or `qa/ci/check-all.sh` on Unix, then record exact commands and results. Use `qa/ci/check-tests.*` or `qa/ci/check-examples.*` separately only when isolating failures.
