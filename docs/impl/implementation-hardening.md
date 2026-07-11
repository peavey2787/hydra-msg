# HYDRA-MSG implementation hardening profile

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
- [Anonymous authorization](../spec/anonymous-authorization.md)

This document defines implementation controls beyond wire correctness.

## 1. Build and dependency policy

- Stable pinned Rust toolchain and complete lockfile.
- `unsafe_code = "deny"` except one separately audited backend FFI crate.
- Reproducible release build with recorded compiler, linker, target, flags,
  source revision, dependency/SBOM hash, and backend evidence.
- Dependency license, advisory, provenance, and abandoned-package checks through the supply-chain gate.
- No default feature may silently select another primitive or encoding.

## 2. Parser policy

- Parse from bounded slices with checked addition/multiplication.
- Validate class and exact record length before allocation.
- Reject duplicate fields, noncanonical order, unknown enum values/bits,
  nonzero reserved bytes/padding, trailing bytes, and integer overflow.
- Cap fragments, signatures, roster entries, tree nodes, skipped keys, and
  pending objects before cryptographic work.
- Never deserialize wire bytes through native struct layout.

## 3. Secret handling

The rules in `memory-zeroization.md` are mandatory. Secret types are
non-copyable, non-serializable, private-field, zeroizing, and either omit
formatting or print a constant redaction. Logs, panics, traces, metrics, crash
reports, and allocator diagnostics never contain secret or plaintext bytes.

## 4. Side channels

Secret-dependent cryptographic work and comparisons are constant-time.
Public class, version, and length checks may branch. Authentication failure
details are local and rate-limited; peers receive a uniform failure. CPU
dispatch is pinned to reviewed implementations per target.

## 5. Concurrency

One owner mutates each chain or group transition. Send indices are reserved
atomically; receive candidates are provisional. Cancellation, timeout, panic,
and task drop invoke the same cleanup as an ordinary failure. Lock ordering is
documented and model-tested; no callback occurs while holding secret-state
locks.

## 6. Files and IPC

Private files use least privilege, exclusive creation, no-follow semantics,
atomic replace, directory fsync where durability matters, and explicit format
bounds. Secrets are not placed in environment variables, command arguments,
temporary files, shared clipboard, or inherited handles. IPC peers are
authenticated and receive only the minimum operation/result.

## 7. Verification

Release CI requires unit/property tests, state-machine model tests, malformed
corpus tests, fuzzing, sanitizers, concurrency tests, fault injection at every
commit boundary, secret-log scanning, and complete frozen-vector agreement.
Coverage numbers alone are not evidence of security.

## 8. Operational hardening

Run least-privileged, isolate crypto processing, minimize network exposure,
disable unnecessary dumps/debugging, apply OS sandboxing, and enforce
`abuse-and-rate-limits.md`. Security updates to OS, compiler, backend, and
dependencies follow an expedited reviewed release path.
