# Browser lifecycle E2E evidence

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)
- [Release criteria](../release/release-criteria.md)
- [Browser lifecycle policy](../evidence/wasm-browser-lifecycle-policy.md)

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

Run an explicit parallel stress pass without changing the release-evidence default:

```bash
HYDRA_BROWSER_WORKERS=3 HYDRA_RUN_BROWSER_E2E=1 \
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


## Firefox transaction determinism

Each lifecycle test uses a distinct IndexedDB database name so a failed or retried test cannot leave state that blocks the next case. Stale compare-and-swap writes queue no mutation; where supported, the adapter explicitly commits that no-write transaction and reports the stale revision only from the transaction's final completion event. Browsers without `IDBTransaction.commit()` use normal automatic commit semantics.

GitHub Actions retains an HTML report, failure screenshots, and an `on-first-retry` trace. Those diagnostics are uploaded even when the browser job fails.
