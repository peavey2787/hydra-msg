# Miri, sanitizer, and fault-injection gate

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)
- [Supply-chain policy](../release/supply-chain-policy.md)

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

## Default Miri path

Miri is mandatory by default for the standalone memory-safety gate and for the
release pipeline. The shared gate automatically installs the minimal nightly
toolchain and the nightly `miri` component through `rustup` if they are missing.
The installation is idempotent and is skipped when the required tooling is
already available.

```bash
./qa/ci/reliability/check-memory-safety.sh
```

`HYDRA_RUN_MIRI=1` remains accepted as an explicit enable, but it is no longer
required. Set `HYDRA_RUN_MIRI=0` only for an intentional local opt-out; such a
run is not valid release Miri evidence. The shared release orchestrator uses
that explicit opt-out only when the dedicated Miri section already passed and
the following sanitizer section would otherwise repeat the same Miri work.

Set `HYDRA_AUTO_INSTALL_RUST_TOOLS=0` only in deliberately locked-down
environments where validation must fail instead of installing a missing nightly
toolchain/component.

By default the gate runs Miri over the low-level crates that are most useful for
undefined-behavior detection without exercising browser or filesystem adapters:

```text
hydra-core
hydra-envelope
hydra-session
```

The package set can be overridden for release-candidate evidence:

```bash
HYDRA_MIRI_PACKAGES="hydra-core hydra-envelope hydra-session hydra-group hydra-msg" \
./qa/ci/reliability/check-memory-safety.sh
```

The default `MIRIFLAGS` is `-Zmiri-disable-isolation`, which allows tests that
need OS randomness. Release notes should record any custom `MIRIFLAGS` used.

### Nightly pinning and cache isolation

The release gate must not execute a multi-hour Miri tranche against the moving
`+nightly` alias. At the start of a Miri run it resolves the current nightly
`commit-date`, `commit-hash`, and host, then maps that exact compiler commit to
the matching immutable rustup nightly archive. The rustc `commit-date` is a
compiler/source commit date; rustup's `nightly-YYYY-MM-DD` suffix is an archive
date, so those dates must not be assumed to be identical. The gate probes nearby
archive dates (normally the following day first), requires an exact rustc commit
and host match, installs `miri` and `rust-src` for that matched dated toolchain,
and uses it for `cargo miri setup`, unit tests, and doctests. Set
`HYDRA_MIRI_TOOLCHAIN=nightly-YYYY-MM-DD` only when deliberately overriding this
mapping; the override is still required to match the resolved compiler commit.

The Miri sysroot and Cargo target directory are isolated under
`target/miri-release/` and keyed by the exact rustc commit. A sysroot created by
one compiler therefore cannot be reused by another compiler. `cargo miri setup`
is executed explicitly before tests; if setup fails once, only that commit-keyed
sysroot is removed and rebuilt. This follows Miri's documented recovery for
`found crate std compiled by an incompatible version of rustc` failures while
avoiding an unconditional full clean on every release run.

The selected toolchain and cache paths are recorded in
`target/memory-safety/miri-toolchain.txt`.

When Miri itself is the failed release section, resume from that section with:

```powershell
.\qa\ci\check-all.ps1 -From miri -DeepFuzz
```

That reruns Miri using one pinned compiler, then continues with sanitizers,
browser, coverage, mutation, and deep fuzz evidence.

## Optional sanitizer path

Sanitizer runs are also opt-in for the standalone gate. When selected, the
shared gate automatically installs minimal nightly Rust and the nightly
`rust-src` component through `rustup` when needed. AddressSanitizer is the
default, and the default target is the actual nightly host target on supported native hosts.
On Windows, the release gate deliberately uses a supported Linux sanitizer target
through Docker or WSL, as described below.

```bash
HYDRA_RUN_SANITIZERS=1 ./qa/ci/reliability/check-memory-safety.sh
```

Defaults:

```text
HYDRA_SANITIZER=address
HYDRA_SANITIZER_TARGET=<nightly host target>
HYDRA_SANITIZER_PACKAGES="hydra-core hydra-envelope hydra-session hydra-msg"
```

`HYDRA_SANITIZER_TARGET` remains overrideable for an explicitly provisioned
cross-target on non-Windows hosts. Windows sanitizer evidence intentionally uses
the supported `x86_64-unknown-linux-gnu` target. `HYDRA_AUTO_INSTALL_RUST_TOOLS=0`
disables automatic nightly tool/component installation.

On Windows, the native `x86_64-pc-windows-msvc` target is **not** used for
Rust AddressSanitizer release evidence. Rust's supported AddressSanitizer target
matrix does not include Windows/MSVC, so mixing rustc sanitizer instrumentation
with the Visual Studio C++ ASan runtime is not accepted as release evidence.
Native Windows crash-consistency, persistence, and ordinary workspace tests still
run on Windows; the sanitizer tranche runs the same Rust crates on the supported
`x86_64-unknown-linux-gnu` target through an isolated Linux backend.

The Windows host chooses the backend with
`HYDRA_WINDOWS_SANITIZER_BACKEND=auto|docker|wsl` (default: `auto`):

- `docker` is preferred when a working Docker daemon is available. The default
  image is the Rust Project nightly image
  `rustlang/rust:nightly-bookworm-2026-08-17`; override it with
  `HYDRA_WINDOWS_SANITIZER_DOCKER_IMAGE` when deliberately pinning a different
  reviewed image.
- `wsl` is the fallback when a usable WSL Linux distribution is available. The
  gate installs a minimal nightly Rust toolchain/rust-src inside that WSL user
  environment when needed, consistent with the repository's existing automatic
  Rust-tool policy.

Both backends run:

```text
RUSTFLAGS=-Zsanitizer=address
cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu
```

for `hydra-core`, `hydra-envelope`, `hydra-session`, and `hydra-msg` by default.
The selected backend and supported target are recorded in
`target/memory-safety/windows-sanitizer-backend.txt` as release evidence.

The gate intentionally does not install, copy, or substitute Visual Studio
`clang_rt.asan*.dll` files. Those runtimes are for MSVC C/C++ AddressSanitizer;
forcing them into an unsupported Rust Windows sanitizer target previously caused
runtime-version and installer failures and is not considered valid Rust sanitizer
evidence.

If neither Docker nor WSL is available, the gate fails closed with instructions
to start one of those supported Linux backends. Set
`HYDRA_WINDOWS_SANITIZER_BACKEND=docker` or `wsl` to require a specific backend.

### Resume after a sanitizer-host prerequisite failure

When the `miri` release section has already passed and the sanitizer section
stopped on a host/backend prerequisite, resume the release pipeline at the
sanitizer section instead of repeating earlier gates:

```powershell
.\qa\ci\check-all.ps1 -From sanitizers -DeepFuzz
```

This reruns sanitizer evidence and then continues with browser, coverage,
mutation, and deep fuzz evidence.

## Pass condition

The memory-safety gate passes when:

- the mandatory fault-injection crash-consistency tests pass;
- failpoints remain test-only;
- documentation names the Miri, sanitizer, and fault-injection procedure;
- release-candidate evidence includes successful Miri logs (Miri runs by default);
- release-candidate evidence includes `HYDRA_RUN_SANITIZERS=1` logs;
- any skipped nightly gate has an explicit release-blocking disposition.

The gate is part of `qa/ci/core/check-tests.*`, so it is executed before
example validation and before the final deterministic fuzz gate.

