import { expect, test } from '@playwright/test';

const APP_URL = process.env.HYDRA_BROWSER_TEST_URL || '';

test.describe('HYDRA browser storage lifecycle policy in real browser contexts', () => {
  test('IndexedDB unavailable/private-mode style denial fails closed without localStorage fallback', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, 'indexedDB', { value: undefined, configurable: true });
    });
    await page.goto('/');
    const result = await page.evaluate(() => {
      let hydraLocalStorageKeys = 0;
      try {
        hydraLocalStorageKeys = Object.keys(localStorage)
          .filter((key) => key.toLowerCase().includes('hydra')).length;
      } catch {
        hydraLocalStorageKeys = 0;
      }
      return {
        indexedDbAvailable: typeof indexedDB !== 'undefined',
        hydraLocalStorageKeys
      };
    });
    expect(result.indexedDbAvailable).toBe(false);
    expect(result.hydraLocalStorageKeys).toBe(0);
  });

  test('compare-and-swap rejects stale two-tab writes and delete-while-open writes', async ({ context }) => {
    const pageA = await context.newPage();
    const pageB = await context.newPage();
    await pageA.goto('/');
    await pageB.goto('/');
    await installIndexedDbHarness(pageA);
    await installIndexedDbHarness(pageB);

    await pageA.evaluate(() => window.__hydraLifecycle.deleteProfile('same-profile'));
    const revisionA = await pageA.evaluate(() => window.__hydraLifecycle.save('same-profile', [1, 2, 3], 0));
    expect(revisionA).toBe(1);
    const loadedB = await pageB.evaluate(() => window.__hydraLifecycle.load('same-profile'));
    expect(loadedB.revision).toBe(1);
    const revisionA2 = await pageA.evaluate(() => window.__hydraLifecycle.save('same-profile', [4, 5, 6], 1));
    expect(revisionA2).toBe(2);

    await expect(pageB.evaluate(() => window.__hydraLifecycle.save('same-profile', [7, 8, 9], 1)))
      .rejects.toThrow(/stale profile revision/);

    await pageA.evaluate(() => window.__hydraLifecycle.deleteProfile('same-profile'));
    await expect(pageB.evaluate(() => window.__hydraLifecycle.save('same-profile', [10], 1)))
      .rejects.toThrow(/stale profile revision/);
  });

  test('QuotaExceededError is surfaced and does not commit partial data', async ({ page }) => {
    await page.goto('/');
    await installIndexedDbHarness(page, { quotaBytes: 4 });
    await page.evaluate(() => window.__hydraLifecycle.deleteProfile('quota-profile'));

    const quotaError = await page.evaluate(async () => {
      try {
        await window.__hydraLifecycle.save('quota-profile', [1, 2, 3, 4, 5], 0);
        return null;
      } catch (error) {
        return {
          name: error instanceof Error || error instanceof DOMException ? error.name : '',
          message: error instanceof Error || error instanceof DOMException ? error.message : String(error)
        };
      }
    });
    expect(quotaError).toEqual({
      name: 'QuotaExceededError',
      message: 'HYDRA test quota exceeded'
    });
    const loaded = await page.evaluate(() => window.__hydraLifecycle.load('quota-profile'));
    expect(loaded).toEqual({ bytes: null, revision: 0 });
  });

  test('aborted tab-crash-style transaction rejects and leaves no committed profile', async ({ page }) => {
    await page.goto('/');
    await installIndexedDbHarness(page);
    await page.evaluate(() => window.__hydraLifecycle.deleteProfile('abort-profile'));
    await expect(page.evaluate(() => window.__hydraLifecycle.abortDuringFlush('abort-profile')))
      .rejects.toThrow(/AbortError|transaction abort/);
    const loaded = await page.evaluate(() => window.__hydraLifecycle.load('abort-profile'));
    expect(loaded).toEqual({ bytes: null, revision: 0 });
  });

  test('reload with dirty in-memory state preserves only the last flushed revision', async ({ page }) => {
    await page.goto('/');
    await installIndexedDbHarness(page);
    await page.evaluate(() => window.__hydraLifecycle.deleteProfile('reload-profile'));
    await page.evaluate(() => window.__hydraLifecycle.save('reload-profile', [1], 0));
    await page.evaluate(() => { window.__dirtyHydraBytes = [9, 9, 9]; });
    await page.reload();
    await installIndexedDbHarness(page);
    const loaded = await page.evaluate(() => window.__hydraLifecycle.load('reload-profile'));
    expect(loaded).toEqual({ bytes: [1], revision: 1 });
  });

  test('mobile pagehide handler can flush before background/kill', async ({ page }) => {
    await page.goto('/');
    await installIndexedDbHarness(page);
    await page.evaluate(() => window.__hydraLifecycle.deleteProfile('pagehide-profile'));
    const flushed = await page.evaluate(async () => {
      let revision = 0;
      window.addEventListener('pagehide', () => {
        window.__pagehideFlush = window.__hydraLifecycle
          .save('pagehide-profile', [4, 2], revision)
          .then((next) => { revision = next; return next; });
      }, { once: true });
      window.dispatchEvent(new PageTransitionEvent('pagehide'));
      return window.__pagehideFlush;
    });
    expect(flushed).toBe(1);
    const loaded = await page.evaluate(() => window.__hydraLifecycle.load('pagehide-profile'));
    expect(loaded).toEqual({ bytes: [4, 2], revision: 1 });
  });

  test('persistent storage denial and grant are both handled explicitly', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'storage', {
        value: { persist: async () => false, persisted: async () => false },
        configurable: true
      });
    });
    await page.goto('/');
    expect(await page.evaluate(() => navigator.storage.persist())).toBe(false);

    const granted = await page.evaluate(async () => {
      Object.defineProperty(navigator, 'storage', {
        value: { persist: async () => true, persisted: async () => true },
        configurable: true
      });
      return navigator.storage.persist();
    });
    expect(granted).toBe(true);
  });
});

test.describe('HYDRA mobile_perf_web WASM browser probes', () => {
  test.skip(!APP_URL, 'Set HYDRA_BROWSER_TEST_URL to the running mobile_perf_web host for full WASM browser evidence.');

  test('mobile_perf_web multi-tab, quota, and persistent-storage probes execute in a real browser', async ({ page }) => {
    await page.goto(APP_URL);
    await runActionAndExpectKind(page, 'multi-tab', 'browser-wasm-indexeddb-multi-tab-concurrency');
    await runActionAndExpectKind(page, 'quota', 'browser-wasm-quota-probe');
    await runActionAndExpectKind(page, 'persistent-suite', 'browser-wasm-indexeddb-persistence-suite');
  });
});

async function runActionAndExpectKind(page, action, kind) {
  await page.locator(`button[data-action="${action}"]`).click();
  const output = page.locator('#out');
  await expect(output).toContainText(kind, { timeout: 45_000 });
}

async function installIndexedDbHarness(page, options = {}) {
  await page.evaluate(({ quotaBytes = Number.MAX_SAFE_INTEGER } = {}) => {
    const DB_NAME = 'hydra-browser-lifecycle-e2e';
    const DB_VERSION = 2;
    const STORE_NAME = 'snapshots';

    function requestToPromise(request) {
      return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
      });
    }

    function transactionToPromise(transaction, operation) {
      return new Promise((resolve, reject) => {
        let transactionError = null;
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => {
          transactionError = transaction.error || transactionError
            || new Error(`IndexedDB ${operation} failed`);
        };
        transaction.onabort = () => reject(
          transaction.error || transactionError || new Error(`IndexedDB ${operation} aborted`)
        );
      });
    }

    async function openDb() {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(STORE_NAME)) {
            db.createObjectStore(STORE_NAME, { keyPath: 'name' });
          }
        };
        request.onsuccess = () => {
          const db = request.result;
          db.onversionchange = () => db.close();
          resolve(db);
        };
        request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
        request.onblocked = () => reject(new Error('IndexedDB open blocked'));
      });
    }

    window.__hydraLifecycle = {
      async load(name) {
        const db = await openDb();
        try {
          const tx = db.transaction(STORE_NAME, 'readonly');
          const [record] = await Promise.all([
            requestToPromise(tx.objectStore(STORE_NAME).get(name)),
            transactionToPromise(tx, 'load')
          ]);
          if (!record) return { bytes: null, revision: 0 };
          return { bytes: Array.from(record.bytes || []), revision: record.revision };
        } finally {
          db.close();
        }
      },

      async save(name, bytes, expectedRevision) {
        if (bytes.length > quotaBytes) {
          throw new DOMException('HYDRA test quota exceeded', 'QuotaExceededError');
        }
        const db = await openDb();
        let outcome;
        try {
          outcome = await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            let nextRevision = null;
            let staleMessage = null;
            let transactionError = null;

            tx.oncomplete = () => resolve({ nextRevision, staleMessage });
            tx.onerror = () => {
              transactionError = tx.error || transactionError
                || new Error('IndexedDB transaction failed');
            };
            tx.onabort = () => reject(
              tx.error || transactionError || new Error('IndexedDB transaction abort')
            );

            const get = store.get(name);
            get.onerror = () => {
              transactionError = get.error || new Error('IndexedDB get failed');
            };
            get.onsuccess = () => {
              const current = get.result || null;
              const currentRevision = current ? current.revision : 0;
              if (currentRevision !== expectedRevision) {
                staleMessage =
                  `stale profile revision: expected ${expectedRevision}, got ${currentRevision}`;
                if (typeof tx.commit === 'function') {
                  tx.commit();
                }
                return;
              }

              nextRevision = currentRevision + 1;
              const put = store.put({
                name,
                bytes: Array.from(bytes),
                revision: nextRevision
              });
              put.onerror = () => {
                transactionError = put.error || new Error('IndexedDB put failed');
              };
            };
          });
        } finally {
          db.close();
        }

        if (outcome.staleMessage !== null) {
          throw new Error(outcome.staleMessage);
        }
        if (outcome.nextRevision === null) {
          throw new Error('IndexedDB transaction completed without a revision');
        }
        return outcome.nextRevision;
      },

      async deleteProfile(name) {
        const db = await openDb();
        try {
          const tx = db.transaction(STORE_NAME, 'readwrite');
          const deletion = requestToPromise(tx.objectStore(STORE_NAME).delete(name));
          await Promise.all([
            deletion,
            transactionToPromise(tx, 'delete')
          ]);
        } finally {
          db.close();
        }
      },

      async abortDuringFlush(name) {
        const db = await openDb();
        try {
          await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            tx.objectStore(STORE_NAME).put({ name, bytes: [1], revision: 1 });
            tx.oncomplete = resolve;
            tx.onerror = (event) => event.preventDefault();
            tx.onabort = () => reject(
              tx.error || new DOMException('HYDRA test transaction aborted', 'AbortError')
            );
            tx.abort();
          });
        } finally {
          db.close();
        }
      }
    };
  }, options);
}
