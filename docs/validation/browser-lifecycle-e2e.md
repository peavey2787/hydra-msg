# Browser lifecycle E2E evidence

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
- [Validation criteria](release-criteria.md)
- [WASM browser lifecycle policy](../../qa/evidence/wasm-browser-lifecycle-policy.md)

HYDRA keeps a static browser lifecycle gate in normal `check-all`, and adds real-browser Playwright evidence for release candidates.

The Playwright suite lives in `qa/browser/playwright/` and exercises actual browser contexts for:

- IndexedDB unavailable/private-browsing-style denial.
- `QuotaExceededError` handling.
- Two tabs writing the same profile.
- Stale revision conflict.
- Deleting a profile while another tab has it open.
- Transaction abort / tab-crash-style flush failure.
- Reload with dirty in-memory state.
- Mobile-like `pagehide` flush before background/kill.
- Persistent storage denied.
- Persistent storage granted.

IndexedDB is unavailable on opaque origins such as `about:blank`. The test configuration therefore starts a repository-owned loopback HTTP server and runs lifecycle cases at `http://127.0.0.1:4173` by default. The static gate rejects any regression back to `about:blank`.

The portable default project matrix is:

- Chromium desktop.
- Firefox desktop.
- Chromium with the Pixel 5 mobile profile.

WebKit remains available as an explicit project, but it is not part of the portable default because Playwright's fallback WebKit build requires native libraries that are unavailable on some otherwise-supported developer distributions, including Devuan installations detected as an unsupported Linux host. Run the full cross-engine matrix on a Playwright-supported host or official Playwright container.

The Playwright package is exact-version pinned and committed with `package-lock.json`. The gate uses `npm ci` and installs only the browser binaries selected by `HYDRA_BROWSER_PROJECTS`; the mobile Chromium project reuses the Chromium binary.

The full WASM app probe is enabled by setting `HYDRA_BROWSER_TEST_URL` to a running `examples/mobile_perf_web` host. Without that URL, the browser-level lifecycle tests still run, and the WASM app probe is skipped.

## Run

First-time setup:

```bash
./scripts/setup-dev-env.sh
```

Run the portable real-browser evidence gate:

```bash
HYDRA_RUN_BROWSER_E2E=1 ./qa/ci/reliability/check-browser-e2e.sh
```

PowerShell:

```powershell
$env:HYDRA_RUN_BROWSER_E2E=1
.\qa\ci\reliability\check-browser-e2e.ps1
```

On Linux hosts that need native packages for the selected browsers:

```bash
HYDRA_PLAYWRIGHT_INSTALL_DEPS=1 HYDRA_RUN_BROWSER_E2E=1 ./qa/ci/reliability/check-browser-e2e.sh
```

Run the full desktop/mobile cross-engine matrix on a supported host:

```bash
HYDRA_BROWSER_PROJECTS=chromium,firefox,webkit,mobile-chromium \
HYDRA_PLAYWRIGHT_INSTALL_DEPS=1 \
HYDRA_RUN_BROWSER_E2E=1 \
./qa/ci/reliability/check-browser-e2e.sh
```

Run a narrower project while debugging:

```bash
HYDRA_BROWSER_PROJECTS=chromium HYDRA_RUN_BROWSER_E2E=1 \
./qa/ci/reliability/check-browser-e2e.sh
```

A preinstalled browser executable can be selected without changing the test code:

```bash
HYDRA_BROWSER_PROJECTS=chromium \
HYDRA_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium \
HYDRA_SKIP_PLAYWRIGHT_INSTALL=1 \
HYDRA_RUN_BROWSER_E2E=1 \
./qa/ci/reliability/check-browser-e2e.sh
```

Equivalent executable overrides are available as `HYDRA_FIREFOX_EXECUTABLE_PATH` and `HYDRA_WEBKIT_EXECUTABLE_PATH`.

Full WASM app evidence:

```bash
HYDRA_BROWSER_TEST_URL=http://127.0.0.1:PORT HYDRA_RUN_BROWSER_E2E=1 \
./qa/ci/reliability/check-browser-e2e.sh
```

Replace `PORT` with the `examples/mobile_perf_web` host port.

For a separately managed lifecycle-test origin, set `HYDRA_BROWSER_TEST_ORIGIN` to that trusted HTTP(S) origin. The repository-owned loopback server is disabled when this override is present.
