# HYDRA-MSG WASM/browser lifecycle policy

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

Status: production hardening policy and regression gate for browser persistence.

HYDRA browser persistence stores one opaque authenticated-encrypted chunked state container per
profile in IndexedDB. Browsers are not filesystems: storage can be unavailable,
evicted, blocked by privacy mode, denied persistent-storage status, or opened by
multiple tabs at once. The policy is therefore fail-closed durability, not silent
best-effort persistence.

## Required behavior

| Browser condition | Required HYDRA behavior | Regression coverage |
| --- | --- | --- |
| Private browsing or storage disabled | `openPersistent()` fails with a storage error; no plaintext, `localStorage`, or durable-looking memory fallback. | `browserLifecycleStatus`, quota/lifecycle probe, static gate, Playwright browser-context denial test. |
| Storage eviction or user-cleared site data | Missing IndexedDB record opens as a fresh profile only when the app intentionally opens that name; recovery is encrypted backup import. | WASM docs and lifecycle policy gate. |
| `QuotaExceededError` | `flush()` returns an error, keeps the wrapper dirty, and never writes plaintext fallback state. | crash-consistency probe, user-facing quota error path, Playwright quota test. |
| Multiple tabs writing same profile | Each record has a non-secret monotonic revision; `flush()` uses IndexedDB readwrite compare-and-swap and rejects stale writers. | `runMultiTabConcurrencyProbe` and Playwright two-page CAS test. |
| Tab crash during flush | IndexedDB transaction abort leaves previous snapshot authoritative. | `runCrashConsistencyProbe` and Playwright transaction-abort test. |
| Versioned DB format | DB version is explicit; this pre-v1 format does not preserve legacy records or migrate old metadata fields. | browser lifecycle static gate. |
| Browser denying persistent storage | `requestPersistentStorage()` reports denial; app warns that state is eviction-prone and keeps backup UX visible. | quota/lifecycle probe and Playwright denial/grant test. |
| Mobile background/kill behavior | Apps must `flush()` before backgrounding and still treat backups as the recovery mechanism. | WASM docs, lifecycle policy gate, and Playwright `pagehide` test. |

## Multi-tab concurrency invariant

HYDRA must never perform last-writer-wins writes for a persistent browser
profile. `openPersistent()` records the current profile revision. `flush()` must:

1. open one IndexedDB `readwrite` transaction;
2. read the current record;
3. compare the durable revision with the wrapper's loaded revision;
4. write the encrypted snapshot only when the revisions match; and
5. return a stale-profile error when another tab, worker, or page instance has
   already advanced the profile.

A stale wrapper remains dirty. The app must not present its changes as durable.
The app may let the user export an encrypted backup, discard the local dirty
state, or reopen the profile and repeat the intended operation.

## Non-goals

- IndexedDB metadata is not a cryptographic freshness anchor against a malicious
  browser or host.
- HYDRA does not merge divergent browser snapshots automatically.
- HYDRA does not hide browser-origin, tab, timing, quota, or eviction metadata.
- HYDRA does not guarantee persistence after user site-data deletion, private
  browsing teardown, OS storage pressure, or mobile process kill.

## App responsibilities

Browser apps must:

- call `await hydra.flush()` at transaction boundaries and before backgrounding;
- surface stale-profile, quota, blocked-open, and storage-unavailable errors;
- offer encrypted backup export/import for recovery and portability;
- rate-limit carrier ingress and bound app queues outside HYDRA; and
- avoid opening the same persistent profile in multiple tabs unless they are
  prepared to handle stale-profile conflicts.

## Gates

The static gate is `qa/ci/reliability/check-browser-lifecycle.sh` with PowerShell parity in
`qa/ci/reliability/check-browser-lifecycle.ps1`. It also invokes the static
Playwright evidence gate in `qa/ci/reliability/check-browser-e2e.sh`.

Release-candidate real-browser evidence is opt-in:

```bash
HYDRA_RUN_BROWSER_E2E=1 ./qa/ci/reliability/check-browser-e2e.sh
```

Set `HYDRA_BROWSER_TEST_URL` to a running `examples/mobile_perf_web` host to
include the full WASM app probes.
