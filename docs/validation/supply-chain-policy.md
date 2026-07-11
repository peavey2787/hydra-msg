# HYDRA-MSG supply-chain policy

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


HYDRA-MSG treats dependency provenance, advisories, yanked crates, duplicate
versions, and license compatibility as release-blocking supply-chain evidence.
The mandatory local gate is:

```bash
./qa/ci/security/check-supply-chain.sh
```

PowerShell:

```powershell
.\qa\ci\security\check-supply-chain.ps1
```

The gate is also called by `qa/ci/core/check-tests.*`, so it is part of `check-all`. In the release-complete `check-all` order, supply-chain checks run before the expensive release-evidence gates; the overnight coverage-guided fuzz campaign remains the final gate.

## Required tools

The gate requires:

```bash
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

For full first-time developer setup, run:

```bash
./scripts/setup-dev-env.sh
```

PowerShell:

```powershell
.\scripts\setup-dev-env.ps1
```

The scripts intentionally fail closed if either tool is missing. Production
validation evidence must name the versions of `cargo-audit`, `cargo-deny`, and
Rust used for the run.

## Project license

The workspace license is:

```text
GPL-2.0-or-later
```

This means HYDRA-MSG is licensed under GPL version 2 or, at the recipient's
option, any later GPL version. The `or-later` form avoids unnecessary
incompatibility with common Rust ecosystem dependencies that use permissive
licenses such as MIT and Apache-2.0.

## Advisory policy

`cargo audit --deny warnings` must pass with no unresolved advisory warning.
Any advisory exception must be temporary, justified in writing, dated, assigned
an owner, and removed as soon as the patched dependency is available.

`cargo deny check advisories` also runs so the Cargo-deny policy and RustSec
advisory state remain aligned.

## License policy

`deny.toml` is the canonical dependency license policy. Allowed dependency
licenses are intentionally narrow and include the common permissive licenses
used by the Rust ecosystem plus the HYDRA project license.

New dependency licenses require an explicit policy update and review before
merge. Unknown licenses fail closed.

## Ban and source policy

`cargo deny` enforces:

```text
yanked crates denied
unknown registries denied
unknown Git sources denied
wildcard dependency versions denied
multiple dependency versions warned and reviewed
```

Multiple versions are currently a warning rather than a hard deny because some
cryptographic and WASM dependencies can legitimately pull parallel major
versions during pre-1.0 development. Release sign-off must review the duplicate
version report and either remove avoidable duplicates or record why they remain.

## Adding dependencies

Before adding a dependency, record why it is necessary and verify:

```text
license is allowed by deny.toml
crate is not yanked
crate has no unresolved vulnerability/advisory warning
source is crates.io or an explicitly approved source
version is pinned according to HYDRA's lock-file policy
it does not introduce avoidable duplicate major versions
```
