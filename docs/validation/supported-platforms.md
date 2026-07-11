# HYDRA-MSG supported platforms

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

Supported platforms are the targets for which a release has validation evidence. A platform is not production-supported just because the code compiles there once.

## Intended support matrix

| Surface | Intended support | Evidence required for production support |
|---|---|---|
| Rust native SDK | Linux, Windows, and macOS where Rust and dependencies support the target | Clean workspace validation and release logs for each claimed target. |
| CLI | Same native targets as the Rust SDK | CLI build/run evidence for each claimed target. |
| WASM/browser SDK | Chromium, Firefox, WebKit, and mobile-like Chromium contexts | Portable Playwright evidence covers Chromium, Firefox, and mobile-like Chromium; WebKit evidence is collected explicitly on a Playwright-supported host, plus WASM package verification. |
| Native profile storage | Filesystems that support the tested lock/write/rename/sync behavior | Crash-consistency and same-profile lock tests. |
| Browser persistent storage | IndexedDB-capable browsers | Fail-closed tests for unavailable storage, quota, stale revisions, deletion, reload, and pagehide. |
| Carriers/transports | App responsibility | HYDRA only transports opaque packets; carrier metadata privacy is outside the SDK. |

## Release rule

Each release notes file must list the supported platform matrix for that version and point to the evidence logs used for that claim.

## Browser storage rule

The portable local browser gate runs Chromium desktop, Firefox desktop, and mobile-like Chromium. WebKit remains part of the intended support matrix, but release evidence for it must be collected explicitly on a Playwright-supported host or official Playwright container because unsupported Linux fallback builds may require unavailable native libraries.

Browser persistent state requires IndexedDB. HYDRA must fail closed when IndexedDB is unavailable, blocked, quota-limited, stale due to another tab, or deleted while open. HYDRA must not fall back to plaintext, `localStorage`, or durable-looking memory state.

## Native storage rule

Native local state uses encrypted `state.hydra` storage and same-profile locking. Two live native `Hydra::open()` handles for the same data directory are unsupported and must fail closed through the native profile lock.
