# Miri, sanitizer, and fault-injection gate

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
- [Supply-chain policy](supply-chain-policy.md)

HYDRA uses a tiered memory-safety and fault-injection gate. The normal local
validation path always runs targeted fault-injection tests. Miri and sanitizer
runs are heavier nightly gates and are enabled explicitly for release-candidate
evidence.

## Mandatory fault-injection path

`qa/ci/reliability/check-memory-safety.sh` and
`qa/ci/reliability/check-memory-safety.ps1` always verify and run the native
fault-injection crash-consistency tests:

```bash
./qa/ci/reliability/check-memory-safety.sh
```

The mandatory path covers failures during:

```text
write temp file
sync temp file
rename/replace state
sync parent dir
write rollback evidence
import backup
delete identity
delete contact
delete message
```

The failpoints are `#[cfg(test)]` only and must not become production runtime
configuration.

## Optional Miri path

Miri requires nightly Rust and the `miri` component. It is intentionally opt-in
so normal local validation does not depend on nightly tooling or long emulator
runs.

```bash
rustup toolchain install nightly
rustup +nightly component add miri
HYDRA_RUN_MIRI=1 ./qa/ci/reliability/check-memory-safety.sh
```

By default the gate runs Miri over the low-level crates that are most useful for
undefined-behavior detection without exercising browser or filesystem adapters:

```text
hydra-core
hydra-envelope
hydra-session
```

The package set can be overridden for release-candidate evidence:

```bash
HYDRA_RUN_MIRI=1 \
HYDRA_MIRI_PACKAGES="hydra-core hydra-envelope hydra-session hydra-group hydra-msg" \
./qa/ci/reliability/check-memory-safety.sh
```

The default `MIRIFLAGS` is `-Zmiri-disable-isolation`, which allows tests that
need OS randomness. Release notes should record any custom `MIRIFLAGS` used.

## Optional sanitizer path

Sanitizer runs require nightly Rust. The default sanitizer is AddressSanitizer
on the Linux GNU target:

```bash
rustup toolchain install nightly
HYDRA_RUN_SANITIZERS=1 ./qa/ci/reliability/check-memory-safety.sh
```

Defaults:

```text
HYDRA_SANITIZER=address
HYDRA_SANITIZER_TARGET=x86_64-unknown-linux-gnu
HYDRA_SANITIZER_PACKAGES="hydra-core hydra-envelope hydra-session hydra-msg"
```

The selected sanitizer, target, package set, Rust version, and output logs are
release evidence. Other sanitizers may be run by overriding `HYDRA_SANITIZER`
when the host toolchain supports them.

## Pass condition

The memory-safety gate passes when:

- the mandatory fault-injection crash-consistency tests pass;
- failpoints remain test-only;
- documentation names the Miri, sanitizer, and fault-injection procedure;
- release-candidate evidence includes `HYDRA_RUN_MIRI=1` logs;
- release-candidate evidence includes `HYDRA_RUN_SANITIZERS=1` logs;
- any skipped nightly gate has an explicit release-blocking disposition.

The gate is part of `qa/ci/core/check-tests.*`, so it is executed before
example validation and before the final deterministic fuzz gate.
