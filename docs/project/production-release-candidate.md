# Production release-candidate packaging

Status: P14 release-candidate packaging notes.

This document records the packaging boundary for the HYDRA-MSG local app release-candidate worktree.

## 1. Scope

P14 packages the local CLI and local browser GUI as an app release candidate.

This is an application release-candidate milestone only. It does not claim that the HYDRA-MSG cryptographic protocol is finally frozen, independently reviewed, or interoperable with independent implementations.

Protocol release/freeze authority remains in:

```text
docs/validation/release-criteria.md
```

## 2. Source state

The active app surfaces are:

```text
examples/hydra-app/src/cli/
examples/hydra-app/src/gui/
examples/hydra-app/src/services/
examples/hydra-app-core/
```

Protocol and app-domain ownership remains:

```text
docs/spec/          protocol authority
crates/hydra-*      protocol/reference implementation crates
examples/hydra-app-core shared app-domain logic
examples/hydra-app      CLI and local browser GUI presentation/orchestration
qa/                  validation infrastructure and vector tooling
```

P12 removed stale demo/node surfaces and excluded placeholder crates from the production branch. `crates/README.md` is the crate ownership summary.

## 3. Release-candidate commit record

The uploaded archive now contains `.git/` metadata at the repository root, so the release-candidate worktree was committed before this note was finalized.

```text
release-candidate commit: 601495a100623af009355d3870e4a13f1129d9ac
release-candidate tag: <optional annotated tag>
QA command: .\qa\ci\check-all.ps1 -SkipGui
QA result: passed on maintainer machine before P14 packaging request; docs and GUI JavaScript syntax checks passed in the assistant sandbox. Cargo is not installed in the assistant sandbox, so rerun the full QA gate after applying this archive.
```

If additional changes are made after this recorded commit, rerun the QA gate and record the replacement release-candidate commit hash.

## 4. User-facing usage documentation

The root `README.md` documents:

- production status and non-overclaiming language;
- repository layout;
- QA gate commands;
- GUI launch;
- first-run identity setup;
- CLI identity/contact/bootstrap/chat/recovery/config commands;
- public contact-card join-code flow;
- QR-ready bootstrap/join-code flow;
- incoming-message contacts-only/unknown-sender policy;
- whitelist/blacklist management;
- backup, recovery, and rollback boundary;
- security boundaries;
- known limitations.

## 5. Local build/run instructions

Primary validation command:

```powershell
.\qa\ci\check-all.ps1 -SkipGui
```

Launch GUI after checks:

```powershell
cargo run --manifest-path examples/hydra-app/Cargo.toml -- gui
```

Full gate including GUI launch:

```powershell
.\qa\ci\check-all.ps1
```

The maintainer reported that the P13 full non-GUI QA gate was green before P14 began.

## 6. Security boundaries

The release-candidate app remains local-first:

- GUI loopback bind is default;
- non-loopback bind requires `--dangerous-allow-remote`;
- GUI API routes require per-process token checks;
- trust-changing routes retain origin checks;
- identity private material remains encrypted at rest;
- unlock/remember-me behavior is memory-only and never stores passwords;
- contact-card and QR/join-code payloads contain public material only;
- first-run identity creation/import auto-unlocks only in the running app process;
- no production relay/mailbox server is introduced by P14.

## 7. Known limitations

Known limitations remain intentionally documented, not hidden:

- final cryptographic release freeze is not claimed;
- independent backend reproduction and external cryptographic review remain future gates;
- production remote relay/mailbox infrastructure is out of scope;
- network anonymity is out of scope;
- purely local rollback protection cannot defeat rollback of every local file plus every external continuity copy;
- vector artifacts remain subject to the evidence status in `docs/validation/test-vectors.md` and `docs/validation/release-criteria.md`.

## 8. P14 boundary invariant audit

P14 introduces no new cryptographic constants, counters, replay windows, storage versions, key schedules, or wire formats.

The relevant app-release boundaries are documentation and packaging boundaries:

- the README must not imply final cryptographic release freeze;
- local GUI usage must document loopback default and dangerous remote bind separately;
- first-run identity setup must document encrypted-at-rest and password-not-stored behavior;
- contact-card and QR/join-code docs must state that private keys and plaintext secrets are not included;
- known limitations must remain visible;
- the release-candidate commit hash is recorded above before tagging/distribution.
