# Changelog

All notable HYDRA-MSG changes are recorded here for app developers, security reviewers, and release managers.

The format is intentionally simple and follows `docs/validation/release/changelog-policy.md`. HYDRA-MSG is still pre-1.0, so compatibility-breaking changes may happen before the first stable release; every such change must be called out here.

## Unreleased

### Added

- Public Rust SDK facade for identities, contacts, handshakes, encrypted messages, attachments, lobbies, anonymous authorization tokens, encrypted local state, and encrypted backups.
- WASM/JavaScript binding with explicit persistent browser state through IndexedDB and `flush()`.
- Native encrypted state persistence with crash-consistency guards and same-profile open locking.
- Chunked and padded encrypted local-state and backup containers.
- Resource-exhaustion limits for state size, backups, contacts, identities, lobbies, messages, attachments, imports, handshakes, anonymous authorization tokens, route tags, and packet fragments.
- QA gates for formatting, tests, clippy, docs, supply chain, privacy invariants, persistence invariants, crash consistency, browser lifecycle policy, deterministic fuzzing, coverage/mutation manifests, cross-version compatibility, and interop fixtures.
- Rust-only critical-path LCOV threshold enforcement with self-tests; the former Python coverage helper was removed.
- Organized validation documentation under `docs/validation/benchmarks`, `docs/validation/evidence`, `docs/validation/gates`, and `docs/validation/release`.
- Optional release-evidence gates for Miri, sanitizers, coverage reports, mutation testing, real browser Playwright lifecycle tests, and coverage-guided fuzzing.
- Release scripts for source archives, crate package collection, CycloneDX SBOM generation, SHA-256 hash publication, detached GPG checksum signatures, verification, and signed Git tags.
- Release-governance documentation for release checklists, artifacts, signing, SBOMs, reproducible builds, MSRV, supported platforms, dependency updates, security advisories, responsible disclosure, and external review status.
- Root `SECURITY.md` using GitHub Private Vulnerability Reporting for `https://github.com/peavey2787/hydra-msg`.

### Security

- Current implementation backend is `hydra_crypto::RustCryptoBackend`; external review status is tracked per release and must not be claimed unless archived.
- Anonymous authorization currently uses one-time bearer tokens scoped to an action. It is not a blind-credential or ZK anonymous-credential system.
- HYDRA minimizes SDK-visible metadata but does not hide carrier/network metadata such as IP addresses, timing, delivery graph, or traffic volume.

### Release status

- No signed production release has been declared yet.
- Generated SBOMs, release checksums, artifact signatures, signed Git tags, and reproducible-build evidence are release artifacts and are not checked in as static repository files.
