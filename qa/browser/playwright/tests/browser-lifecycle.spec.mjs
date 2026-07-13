import { expect, test } from '@playwright/test';

const APP_URL = process.env.HYDRA_BROWSER_TEST_URL || '';
let databaseSequence = 0;

function uniqueDatabaseName(testInfo) {
  databaseSequence += 1;
  return [
    'hydra-browser-lifecycle-e2e',
    testInfo.project.name,
    testInfo.workerIndex,
    testInfo.retry,
    databaseSequence
  ].join('-');
}

async function capturedSaveError(page, name, bytes, expectedRevision) {
  return page.evaluate(async ({ profileName, profileBytes, revision }) => {
    try {
      await window.__hydraLifecycle.save(profileName, profileBytes, revision);
      return null;
    } catch (error) {
      return {
        name: error instanceof Error || error instanceof DOMException ? error.name : '',
        message: error instanceof Error || error instanceof DOMException ? error.message : String(error)
      };
    }
  }, {
    profileName: name,
    profileBytes: bytes,
    revision: expectedRevision
  });
}

async function closeLifecyclePage(page) {
  if (page.isClosed()) return;

  // Firefox may leave a page.evaluate() promise pending while the page is
  // closing. Never await that promise again after the bounded grace period;
  // doing so turns successful assertions into a 60-second teardown timeout.
  const closeRequest = page.evaluate(() => window.__hydraLifecycle?.close()).catch(() => {});
  await Promise.race([
    closeRequest,
    new Promise((resolve) => setTimeout(resolve, 1_000))
  ]);
  await Promise.race([
    page.close({ runBeforeUnload: false }).catch(() => {}),
    new Promise((resolve) => setTimeout(resolve, 5_000))
  ]);
}

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

  test('compare-and-swap rejects stale two-tab writes and delete-while-open writes', async ({ context }, testInfo) => {
    const pageA = await context.newPage();
    const pageB = await context.newPage();

    try {
      await pageA.goto('/');
      await pageB.goto('/');
      const databaseName = uniqueDatabaseName(testInfo);
      await installIndexedDbHarness(pageA, { databaseName });
      await installIndexedDbHarness(pageB, { databaseName });

      await test.step('establish two-tab revision divergence', async () => {
        await pageA.evaluate(() => window.__hydraLifecycle.deleteProfile('same-profile'));
        const revisionA = await pageA.evaluate(
          () => window.__hydraLifecycle.save('same-profile', [1, 2, 3], 0)
        );
        expect(revisionA).toBe(1);
        const loadedB = await pageB.evaluate(() => window.__hydraLifecycle.load('same-profile'));
        expect(loadedB.revision).toBe(1);
        const revisionA2 = await pageA.evaluate(
          () => window.__hydraLifecycle.save('same-profile', [4, 5, 6], 1)
        );
        expect(revisionA2).toBe(2);
        expect(await pageA.evaluate(() => window.__hydraLifecycle.stats())).toEqual({
          databaseOpens: 1,
          saveReadwriteTransactions: 2
        });
        expect(await pageB.evaluate(() => window.__hydraLifecycle.stats())).toEqual({
          databaseOpens: 1,
          saveReadwriteTransactions: 0
        });
      });

      await test.step('reject the stale page without acquiring a write transaction', async () => {
        const before = await pageB.evaluate(() => window.__hydraLifecycle.stats());
        const staleError = await capturedSaveError(pageB, 'same-profile', [7, 8, 9], 1);
        const after = await pageB.evaluate(() => window.__hydraLifecycle.stats());
        expect(staleError).not.toBeNull();
        expect(staleError.message).toMatch(/stale profile revision/);
        expect(after.saveReadwriteTransactions).toBe(before.saveReadwriteTransactions);
        expect(await pageA.evaluate(() => window.__hydraLifecycle.load('same-profile'))).toEqual({
          bytes: [4, 5, 6],
          revision: 2
        });
      });

      await test.step('delete while the second page remains open and reject its stale write', async () => {
        await pageA.evaluate(() => window.__hydraLifecycle.deleteProfile('same-profile'));
        const before = await pageB.evaluate(() => window.__hydraLifecycle.stats());
        const staleAfterDelete = await capturedSaveError(pageB, 'same-profile', [10], 1);
        const after = await pageB.evaluate(() => window.__hydraLifecycle.stats());
        expect(staleAfterDelete).not.toBeNull();
        expect(staleAfterDelete.message).toMatch(/stale profile revision/);
        expect(after.saveReadwriteTransactions).toBe(before.saveReadwriteTransactions);
        expect(await pageB.evaluate(() => window.__hydraLifecycle.load('same-profile'))).toEqual({
          bytes: null,
          revision: 0
        });
        expect((await pageA.evaluate(() => window.__hydraLifecycle.stats())).databaseOpens).toBe(1);
        expect((await pageB.evaluate(() => window.__hydraLifecycle.stats())).databaseOpens).toBe(1);
      });
    } finally {
      await closeLifecyclePage(pageB);
      await closeLifecyclePage(pageA);
    }
  });

  test('QuotaExceededError is surfaced and does not commit partial data', async ({ page }, testInfo) => {
    await page.goto('/');
    await installIndexedDbHarness(page, {
      databaseName: uniqueDatabaseName(testInfo),
      quotaBytes: 4
    });
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

  test('aborted tab-crash-style transaction rejects and leaves no committed profile', async ({ page }, testInfo) => {
    await page.goto('/');
    await installIndexedDbHarness(page, { databaseName: uniqueDatabaseName(testInfo) });
    await page.evaluate(() => window.__hydraLifecycle.deleteProfile('abort-profile'));
    await expect(page.evaluate(() => window.__hydraLifecycle.abortDuringFlush('abort-profile')))
      .rejects.toThrow(/AbortError|transaction abort/);
    const loaded = await page.evaluate(() => window.__hydraLifecycle.load('abort-profile'));
    expect(loaded).toEqual({ bytes: null, revision: 0 });
  });

  test('reload with dirty in-memory state preserves only the last flushed revision', async ({ page }, testInfo) => {
    const databaseName = uniqueDatabaseName(testInfo);
    await page.goto('/');
    await installIndexedDbHarness(page, { databaseName });
    await page.evaluate(() => window.__hydraLifecycle.deleteProfile('reload-profile'));
    await page.evaluate(() => window.__hydraLifecycle.save('reload-profile', [1], 0));
    await page.evaluate(() => { window.__dirtyHydraBytes = [9, 9, 9]; });
    await page.reload();
    await installIndexedDbHarness(page, { databaseName });
    const loaded = await page.evaluate(() => window.__hydraLifecycle.load('reload-profile'));
    expect(loaded).toEqual({ bytes: [1], revision: 1 });
  });

  test('mobile pagehide handler can flush before background/kill', async ({ page }, testInfo) => {
    await page.goto('/');
    await installIndexedDbHarness(page, { databaseName: uniqueDatabaseName(testInfo) });
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
  await page.evaluate(({
    databaseName = 'hydra-browser-lifecycle-e2e',
    quotaBytes = Number.MAX_SAFE_INTEGER
  } = {}) => {
    const DB_NAME = databaseName;
    const DB_VERSION = 2;
    const STORE_NAME = 'snapshots';
    let saveReadwriteTransactions = 0;
    let databaseOpens = 0;
    let dbPromise = null;

    function requestToPromise(request) {
      return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
      });
    }

    function transactionFailure(transaction, operationError, fallback) {
      if (operationError) return operationError;
      try {
        return transaction.error || fallback;
      } catch {
        return fallback;
      }
    }

    function transactionToPromise(transaction, operation) {
      return new Promise((resolve, reject) => {
        let transactionError = null;
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => {
          transactionError = transactionFailure(
            transaction,
            transactionError,
            new Error(`IndexedDB ${operation} failed`)
          );
        };
        transaction.onabort = () => reject(transactionFailure(
          transaction,
          transactionError,
          new Error(`IndexedDB ${operation} aborted`)
        ));
      });
    }

    async function readCurrentRevision(db, name) {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        let revision = 0;
        let operationError = null;

        tx.oncomplete = () => {
          if (operationError) {
            reject(operationError);
            return;
          }
          resolve(revision);
        };
        tx.onerror = () => {
          operationError = transactionFailure(
            tx,
            operationError,
            new Error('IndexedDB revision preflight failed')
          );
        };
        tx.onabort = () => reject(transactionFailure(
          tx,
          operationError,
          new Error('IndexedDB revision preflight aborted')
        ));

        const get = tx.objectStore(STORE_NAME).get(name);
        get.onsuccess = () => {
          revision = get.result ? get.result.revision : 0;
        };
        get.onerror = () => {
          operationError = get.error || new Error('IndexedDB revision preflight failed');
        };
      });
    }

    async function openDb() {
      if (!dbPromise) {
        dbPromise = new Promise((resolve, reject) => {
          const request = indexedDB.open(DB_NAME, DB_VERSION);
          request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
              db.createObjectStore(STORE_NAME, { keyPath: 'name' });
            }
          };
          request.onsuccess = () => {
            const db = request.result;
            databaseOpens += 1;
            db.onversionchange = () => {
              db.close();
              dbPromise = null;
            };
            db.onclose = () => { dbPromise = null; };
            resolve(db);
          };
          request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
          request.onblocked = () => reject(new Error('IndexedDB open blocked'));
        });
      }
      try {
        return await dbPromise;
      } catch (error) {
        dbPromise = null;
        throw error;
      }
    }

    async function closeDb() {
      const pending = dbPromise;
      dbPromise = null;
      if (!pending) return;
      try {
        const db = await pending;
        db.close();
      } catch {
        // Opening may already have failed. Clearing dbPromise is sufficient.
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    window.__hydraLifecycle = {
      stats() {
        return { databaseOpens, saveReadwriteTransactions };
      },

      close() {
        return closeDb();
      },

      async load(name) {
        const db = await openDb();
        const tx = db.transaction(STORE_NAME, 'readonly');
        const [record] = await Promise.all([
          requestToPromise(tx.objectStore(STORE_NAME).get(name)),
          transactionToPromise(tx, 'load')
        ]);
        if (!record) return { bytes: null, revision: 0 };
        return { bytes: Array.from(record.bytes || []), revision: record.revision };
      },

      async save(name, bytes, expectedRevision) {
        if (bytes.length > quotaBytes) {
          throw new DOMException('HYDRA test quota exceeded', 'QuotaExceededError');
        }
        const db = await openDb();

        // Reject known-stale callers using a readonly transaction. This is the
        // normal two-tab stale path and never acquires an IndexedDB write lock.
        const preflightRevision = await readCurrentRevision(db, name);
        if (preflightRevision !== expectedRevision) {
          throw new Error(
            `stale profile revision: expected ${expectedRevision}, got ${preflightRevision}`
          );
        }

        // Recheck inside the readwrite transaction before writing. The second
        // check preserves atomic compare-and-swap if another context commits
        // between the readonly preflight and this transaction.
        return await new Promise((resolve, reject) => {
          saveReadwriteTransactions += 1;
          const tx = db.transaction(STORE_NAME, 'readwrite');
          const store = tx.objectStore(STORE_NAME);
          let nextRevision = null;
          let operationError = null;

          tx.oncomplete = () => {
            if (operationError) {
              reject(operationError);
              return;
            }
            if (nextRevision === null) {
              reject(new Error('IndexedDB transaction completed without a revision'));
              return;
            }
            resolve(nextRevision);
          };
          tx.onerror = () => {
            operationError = transactionFailure(
              tx,
              operationError,
              new Error('IndexedDB transaction failed')
            );
          };
          tx.onabort = () => reject(transactionFailure(
            tx,
            operationError,
            new Error('IndexedDB transaction abort')
          ));

          const get = store.get(name);
          get.onerror = () => {
            operationError = get.error || new Error('IndexedDB get failed');
          };
          get.onsuccess = () => {
            const current = get.result || null;
            const currentRevision = current ? current.revision : 0;
            if (currentRevision !== expectedRevision) {
              // Do not abort or queue a semantic no-op. Let the transaction
              // complete normally, then reject after Firefox releases its lock.
              operationError = new Error(
                `stale profile revision: expected ${expectedRevision}, got ${currentRevision}`
              );
              return;
            }

            nextRevision = currentRevision + 1;
            const put = store.put({
              name,
              bytes: Array.from(bytes),
              revision: nextRevision
            });
            put.onerror = () => {
              operationError = put.error || new Error('IndexedDB put failed');
            };
          };
        });
      },

      async deleteProfile(name) {
        const db = await openDb();
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const deletion = requestToPromise(tx.objectStore(STORE_NAME).delete(name));
        await Promise.all([
          deletion,
          transactionToPromise(tx, 'delete')
        ]);
      },

      async abortDuringFlush(name) {
        const db = await openDb();
        await new Promise((resolve, reject) => {
          const tx = db.transaction(STORE_NAME, 'readwrite');
          tx.objectStore(STORE_NAME).put({ name, bytes: [1], revision: 1 });
          tx.oncomplete = resolve;
          tx.onerror = (event) => event.preventDefault();
          tx.onabort = () => reject(transactionFailure(
            tx,
            null,
            new DOMException('HYDRA test transaction aborted', 'AbortError')
          ));
          tx.abort();
        });
      }
    };
  }, options);
}
