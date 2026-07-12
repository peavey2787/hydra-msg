#!/usr/bin/env sh
set -eu

. "$(dirname -- "$0")/../lib/repo-root.sh"
hydra_enter_repo_root

require_file() {
  if [ ! -f "$1" ]; then
    echo "required browser E2E file missing: $1" >&2
    exit 1
  fi
}

require_file qa/browser/playwright/package.json
require_file qa/browser/playwright/package-lock.json
require_file qa/browser/playwright/playwright.config.mjs
require_file qa/browser/playwright/scripts/install-browsers.mjs
require_file qa/browser/playwright/scripts/serve-test-origin.mjs
require_file qa/browser/playwright/tests/browser-lifecycle.spec.mjs
require_file crates/hydra-msg/src/browser/persistence.rs

if ! grep -Fq "@playwright/test" qa/browser/playwright/package.json; then
  echo "Playwright test dependency missing" >&2
  exit 1
fi

if grep -Fq "about:blank" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
  echo "browser E2E storage tests must use a real HTTP origin, not about:blank" >&2
  exit 1
fi

for transaction_marker in \
  "operationError || tx.error" \
  "tx.onabort = () => reject"
do
  if ! grep -Fq "$transaction_marker" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
    echo "browser E2E transaction-settlement marker missing: $transaction_marker" >&2
    exit 1
  fi
  if ! grep -Fq "$transaction_marker" crates/hydra-msg/src/browser/persistence.rs; then
    echo "production browser adapter transaction-settlement marker missing: $transaction_marker" >&2
    exit 1
  fi
done


for required_stale_marker in \
  "rejectAndAbortStaleTransaction" \
  "transaction.abort()" \
  "reject(error)" \
  "uniqueDatabaseName" \
  "capturedSaveError"
do
  if ! grep -Fq "$required_stale_marker" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
    echo "browser E2E Firefox-safe stale-CAS marker missing: $required_stale_marker" >&2
    exit 1
  fi
done

for required_adapter_marker in \
  "rejectAndAbortHydraStaleTransaction" \
  "tx.abort()" \
  "reject(error)"
do
  if ! grep -Fq "$required_adapter_marker" crates/hydra-msg/src/browser/persistence.rs; then
    echo "production browser adapter Firefox-safe stale-CAS marker missing: $required_adapter_marker" >&2
    exit 1
  fi
done

for required_config in "baseURL" "webServer" "serve-test-origin.mjs" "HYDRA_BROWSER_WORKERS" "workers: workerCount" "trace: 'on-first-retry'" "playwright-report"; do
  if ! grep -Fq "$required_config" qa/browser/playwright/playwright.config.mjs; then
    echo "browser E2E real-origin configuration missing: $required_config" >&2
    exit 1
  fi
done

for required in \
  "IndexedDB unavailable/private-mode style denial" \
  "QuotaExceededError" \
  "compare-and-swap rejects stale two-tab writes" \
  "delete-while-open" \
  "aborted tab-crash-style transaction" \
  "reload with dirty in-memory state" \
  "mobile pagehide handler" \
  "persistent storage denial and grant" \
  "HYDRA_BROWSER_TEST_URL"
do
  if ! grep -Fq "$required" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
    echo "browser E2E scenario missing: $required" >&2
    exit 1
  fi
done

if [ "${HYDRA_RUN_BROWSER_E2E:-0}" != "1" ]; then
  echo "Browser E2E static checks passed. Set HYDRA_RUN_BROWSER_E2E=1 to run Playwright."
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required for HYDRA_RUN_BROWSER_E2E=1" >&2
  exit 1
fi

cd qa/browser/playwright
npm ci

if [ "${HYDRA_SKIP_PLAYWRIGHT_INSTALL:-0}" = "1" ]; then
  echo "Skipping Playwright browser binary install because HYDRA_SKIP_PLAYWRIGHT_INSTALL=1"
else
  npm run install:browsers
fi

npx playwright test
