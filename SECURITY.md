# Security Policy

## Supported Versions

HYDRA-MSG is pre-1.0. Until the first stable production release, security fixes are handled on the latest `main` branch and the latest release candidate.

After `v1.0.0`, this section must list each supported release line and whether it receives security fixes.

## Reporting a Vulnerability

Please do **not** open public GitHub issues, pull requests, discussions, or social posts for security vulnerabilities.

Use GitHub Private Vulnerability Reporting for this public repository:

<https://github.com/peavey2787/hydra-msg/security/advisories/new>

## Response Expectations

For production releases, HYDRA-MSG targets this response process:

| Step | Target |
| --- | --- |
| Initial acknowledgement | Within 7 days |
| Initial triage | Within 14 days |
| Fix and advisory plan | Based on severity, exploitability, and affected versions |
| Public disclosure | Coordinated after a fix, mitigation, or advisory is available |

These are targets, not guarantees. Critical actively exploited issues should be handled as emergency releases.

## Security Scope

Security-sensitive areas include:

- cryptographic primitives and backend usage
- identity creation, import, export, locking, and deletion
- contact cards and contact verification
- handshake offers and answers
- session ratchets, counters, rekeying, replay handling, and closure
- group, lobby, invite, and membership state
- anonymous authorization tokens, nullifiers, revocation, scope, and action binding
- envelope encoding, routing hints, padding, and fragmentation
- encrypted state, backup, restore, rollback protection, and chunked storage
- browser/WASM IndexedDB persistence, multi-tab handling, and lifecycle flush behavior
- native profile locking and stale-writer prevention
- supply-chain integrity, release artifacts, signatures, checksums, and SBOMs

## Out of Scope

The following are normally out of scope unless they demonstrate a concrete HYDRA-MSG security failure:

- carrier/network metadata that HYDRA explicitly documents as app or transport responsibility
- phishing or social-engineering reports unrelated to HYDRA-MSG code or artifacts
- reports against unsupported forks or modified builds
- denial-of-service reports that require already-controlled local code execution and do not bypass documented limits
- vulnerabilities in third-party services used by an app developer but not controlled by this repository

## Disclosure

Please wait for coordinated disclosure through the GitHub advisory process. Public release notes and advisories should identify affected versions, fixed versions, workarounds, artifact hashes, and verification instructions when safe to disclose.
