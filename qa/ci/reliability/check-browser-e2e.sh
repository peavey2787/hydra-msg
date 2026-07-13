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
persistence_facade=crates/hydra-msg/src/browser/persistence.rs
persistence_js=crates/hydra-msg/src/browser/persistence_js.rs
require_file "$persistence_facade"
require_file "$persistence_js"

production_contains() {
  marker=$1
  grep -Fq "$marker" "$persistence_facade" "$persistence_js"
}

if ! grep -Fq "@playwright/test" qa/browser/playwright/package.json; then
  echo "Playwright test dependency missing" >&2
  exit 1
fi

if grep -Fq "about:blank" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
  echo "browser E2E storage tests must use a real HTTP origin, not about:blank" >&2
  exit 1
fi

for transaction_marker in \
  "function transactionFailure" \
  "tx.onabort = () => reject"
do
  if ! grep -Fq "$transaction_marker" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
    echo "browser E2E transaction-settlement marker missing: $transaction_marker" >&2
    exit 1
  fi
  if ! production_contains "$transaction_marker"; then
    echo "production browser adapter transaction-settlement marker missing: $transaction_marker" >&2
    exit 1
  fi
done


for required_stale_marker in \
  "readCurrentRevision" \
  "readonly transaction" \
  "never acquires an IndexedDB write lock" \
  "Recheck inside the readwrite transaction" \
  "uniqueDatabaseName" \
  "capturedSaveError" \
  "saveReadwriteTransactions" \
  "let dbPromise = null" \
  "databaseOpens" \
  "Do not abort or queue a semantic no-op"
do
  if ! grep -Fq "$required_stale_marker" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
    echo "browser E2E readonly-preflight stale-CAS marker missing: $required_stale_marker" >&2
    exit 1
  fi
done

for required_adapter_marker in \
  "readHydraCurrentRevision" \
  "readonly transaction" \
  "avoids acquiring a cross-tab write lock" \
  "Recheck atomically inside the write transaction" \
  "let hydraDbPromise = null" \
  "async function hydraIndexedDb()" \
  "Reuse one connection per browser realm" \
  "No write request is queued"
do
  if ! production_contains "$required_adapter_marker"; then
    echo "production browser adapter readonly-preflight stale-CAS marker missing: $required_adapter_marker" >&2
    exit 1
  fi
done

for forbidden_stale_marker in \
  "settleStaleTransactionOnComplete" \
  "settleHydraStaleTransactionOnComplete" \
  "queueNoOpSettlement" \
  "queueHydraNoOpSettlement" \
  "abortStaleTransactionAndWait" \
  "abortHydraStaleTransactionAndWait" \
  "rejectAndAbortStaleTransaction" \
  "rejectAndAbortHydraStaleTransaction"
do
  if grep -Fq "$forbidden_stale_marker" qa/browser/playwright/tests/browser-lifecycle.spec.mjs \
    || production_contains "$forbidden_stale_marker"; then
    echo "obsolete stale-CAS settlement strategy remains: $forbidden_stale_marker" >&2
    exit 1
  fi
done


# Opening and closing a new connection for every operation caused Firefox to
# leave close-pending connections that blocked the next tab. The harness has
# one versionchange close plus one explicit test-teardown close. Production has
# only the versionchange close because page destruction closes its realm.
spec_close_count=$(grep -Fc "db.close();" qa/browser/playwright/tests/browser-lifecycle.spec.mjs)
production_close_count=$(cat "$persistence_facade" "$persistence_js" | grep -Fc "db.close();")
if [ "$spec_close_count" -ne 2 ]; then
  echo "browser E2E harness must close its cached IndexedDB connection on versionchange and explicit teardown" >&2
  exit 1
fi
if [ "$production_close_count" -ne 1 ]; then
  echo "production browser adapter must close its cached IndexedDB connection only on versionchange" >&2
  exit 1
fi

if grep -Fq "await closeRequest;" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
  echo "Firefox browser E2E teardown must not re-await a timed-out page.evaluate request" >&2
  exit 1
fi

for teardown_marker in \
  "async function closeLifecyclePage" \
  "window.__hydraLifecycle?.close()" \
  "page.close({ runBeforeUnload: false })" \
  "await closeLifecyclePage(pageB)" \
  "await closeLifecyclePage(pageA)"
do
  if ! grep -Fq "$teardown_marker" qa/browser/playwright/tests/browser-lifecycle.spec.mjs; then
    echo "Firefox browser E2E deterministic teardown marker missing: $teardown_marker" >&2
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
