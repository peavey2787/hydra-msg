//! JavaScript/IndexedDB bindings for the WASM persistence adapter.
//!
//! This module owns the browser transaction implementation. Keep the Rust
//! facade and HYDRA error conversion in `persistence.rs`.

use js_sys::{Promise, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = r#"
const HYDRA_DB_NAME = 'hydra-msg';
const HYDRA_DB_VERSION = 2;
const HYDRA_STORE_NAME = 'snapshots';
const HYDRA_MAX_NAME_BYTES = 256;
const HYDRA_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;
const HYDRA_ADAPTER_VERSION = 2;
let hydraDbPromise = null;

function hydraTextEncoder() {
  if (typeof TextEncoder === 'undefined') {
    throw new Error('TextEncoder unavailable');
  }
  return new TextEncoder();
}

function validateHydraSnapshotName(name) {
  if (typeof name !== 'string') {
    throw new Error('HYDRA persistent snapshot name must be a string');
  }
  if (name.length === 0) {
    throw new Error('HYDRA persistent snapshot name must not be empty');
  }
  if (hydraTextEncoder().encode(name).length > HYDRA_MAX_NAME_BYTES) {
    throw new Error('HYDRA persistent snapshot name is too long');
  }
  return name;
}

function validateHydraSnapshotBytes(bytes) {
  const snapshot = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (snapshot.byteLength > HYDRA_MAX_SNAPSHOT_BYTES) {
    throw new Error('HYDRA encrypted snapshot exceeds browser adapter size limit');
  }
  return snapshot;
}

function validateHydraRevision(revision) {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error('HYDRA persistent profile revision is invalid');
  }
  return revision;
}

function hydraRecordRevision(record) {
  if (!record || record.revision === undefined || record.revision === null) {
    throw new Error('HYDRA persistent record revision missing');
  }
  return validateHydraRevision(record.revision);
}

function staleHydraProfileError(name, expectedRevision, actualRevision) {
  return new Error(
    `HYDRA persistent profile stale for ${name}: expected revision ${expectedRevision}, `
    + `found ${actualRevision}. Another tab or worker committed this profile; `
    + 'reopen it before flushing so HYDRA never performs last-writer-wins state loss.'
  );
}

function openHydraIndexedDb() {
  if (!globalThis.indexedDB) {
    throw new Error('IndexedDB unavailable for HYDRA persistent state');
  }
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(HYDRA_DB_NAME, HYDRA_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(HYDRA_STORE_NAME)) {
        db.createObjectStore(HYDRA_STORE_NAME, { keyPath: 'name' });
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        db.close();
        hydraDbPromise = null;
      };
      db.onclose = () => { hydraDbPromise = null; };
      resolve(db);
    };
    request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
    request.onblocked = () => reject(new Error('IndexedDB open blocked by another tab'));
  });
}

async function hydraIndexedDb() {
  // Reuse one connection per browser realm. Firefox can leave a just-closed
  // connection in a close-pending state briefly, which can block the next
  // transaction opened by another tab. A realm-scoped connection removes that
  // open/close race while IndexedDB still serializes transactions atomically.
  if (!hydraDbPromise) {
    hydraDbPromise = openHydraIndexedDb();
  }
  try {
    return await hydraDbPromise;
  } catch (error) {
    hydraDbPromise = null;
    throw error;
  }
}

function transactionFailure(tx, operationError, fallback) {
  if (operationError) return operationError;
  try {
    return tx.error || fallback;
  } catch (_) {
    return fallback;
  }
}

async function readHydraCurrentRevision(db, name) {
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(HYDRA_STORE_NAME, 'readonly');
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
    tx.onabort = () => reject(
      transactionFailure(tx, operationError, new Error('IndexedDB revision preflight aborted'))
    );

    const request = tx.objectStore(HYDRA_STORE_NAME).get(name);
    request.onsuccess = () => {
      try {
        revision = request.result ? hydraRecordRevision(request.result) : 0;
      } catch (error) {
        operationError = error;
        try {
          tx.abort();
        } catch (_) {
          reject(error);
        }
      }
    };
    request.onerror = () => {
      operationError = request.error || new Error('IndexedDB revision preflight failed');
    };
  });
}

export async function hydraIndexedDbLoad(name) {
  name = validateHydraSnapshotName(name);
  const db = await hydraIndexedDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(HYDRA_STORE_NAME, 'readonly');
    let record;
    let operationError = null;

    tx.oncomplete = () => {
      try {
        const result = [];
        if (!record) {
          result[0] = undefined;
          result[1] = 0;
        } else {
          result[0] = new Uint8Array(record.snapshot);
          result[1] = hydraRecordRevision(record);
        }
        resolve(result);
      } catch (error) {
        reject(error);
      }
    };
    tx.onerror = () => {
      operationError = transactionFailure(tx, operationError, new Error('IndexedDB read failed'));
    };
    tx.onabort = () => reject(
      transactionFailure(tx, operationError, new Error('IndexedDB read transaction aborted'))
    );

    const request = tx.objectStore(HYDRA_STORE_NAME).get(name);
    request.onsuccess = () => {
      record = request.result;
    };
    request.onerror = () => {
      operationError = request.error || new Error('IndexedDB read failed');
    };
  });
}

export async function hydraIndexedDbSave(name, bytes, expectedRevision) {
  name = validateHydraSnapshotName(name);
  const snapshot = validateHydraSnapshotBytes(bytes);
  expectedRevision = validateHydraRevision(expectedRevision);
  const db = await hydraIndexedDb();

  // Reject the normal known-stale path through a readonly transaction. This
  // avoids acquiring a cross-tab write lock when no write can be committed.
  const preflightRevision = await readHydraCurrentRevision(db, name);
  if (preflightRevision !== expectedRevision) {
    throw staleHydraProfileError(name, expectedRevision, preflightRevision);
  }

  // Recheck atomically inside the write transaction before committing. This
  // catches a tab/worker that wins the race after the readonly preflight.
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(HYDRA_STORE_NAME, 'readwrite');
    const store = tx.objectStore(HYDRA_STORE_NAME);
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
    tx.onabort = () => reject(
      transactionFailure(tx, operationError, new Error('IndexedDB transaction aborted'))
    );

    const request = store.get(name);
    request.onsuccess = () => {
      try {
        const currentRevision = request.result ? hydraRecordRevision(request.result) : 0;
        if (currentRevision !== expectedRevision) {
          // No write request is queued. Let this readwrite transaction complete
          // normally, then reject from oncomplete after its lock is released.
          operationError = staleHydraProfileError(name, expectedRevision, currentRevision);
          return;
        }
        nextRevision = currentRevision + 1;
        const putRequest = store.put({
          name,
          snapshot,
          revision: nextRevision,
          adapterVersion: HYDRA_ADAPTER_VERSION
        });
        putRequest.onerror = () => {
          operationError = putRequest.error || new Error('IndexedDB write failed');
        };
      } catch (error) {
        operationError = error;
      }
    };
    request.onerror = () => {
      operationError = request.error || new Error('IndexedDB read-before-write failed');
    };
  });
}

export async function hydraIndexedDbDelete(name) {
  name = validateHydraSnapshotName(name);
  const db = await hydraIndexedDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(HYDRA_STORE_NAME, 'readwrite');
    let operationError = null;

    tx.oncomplete = () => resolve();
    tx.onerror = () => {
      operationError = transactionFailure(tx, operationError, new Error('IndexedDB delete failed'));
    };
    tx.onabort = () => reject(
      transactionFailure(tx, operationError, new Error('IndexedDB delete aborted'))
    );

    const request = tx.objectStore(HYDRA_STORE_NAME).delete(name);
    request.onerror = () => {
      operationError = request.error || new Error('IndexedDB delete failed');
    };
  });
}

export async function hydraBrowserLifecycleStatus() {
  const storage = globalThis.navigator && globalThis.navigator.storage;
  const estimate = storage && storage.estimate ? await storage.estimate() : null;
  const persisted = storage && storage.persisted ? await storage.persisted() : null;
  return JSON.stringify({
    adapterVersion: HYDRA_ADAPTER_VERSION,
    indexedDbAvailable: Boolean(globalThis.indexedDB),
    storageEstimateAvailable: Boolean(storage && storage.estimate),
    persistentStorageApiAvailable: Boolean(storage && storage.persist),
    persistentStorageGranted: persisted,
    usage: estimate && estimate.usage !== undefined ? estimate.usage : null,
    quota: estimate && estimate.quota !== undefined ? estimate.quota : null,
    policy: 'HYDRA fails closed on missing IndexedDB, stale profile revision, quota failure, and blocked IndexedDB upgrade; records omit write timestamps; use encrypted backups for eviction/private/mobile recovery.'
  });
}

export async function hydraRequestPersistentStorage() {
  const storage = globalThis.navigator && globalThis.navigator.storage;
  if (!storage || !storage.persist) {
    return false;
  }
  return await storage.persist();
}
"#)]
extern "C" {
    #[wasm_bindgen(catch, js_name = hydraIndexedDbLoad)]
    pub(crate) fn indexed_db_load(name: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraIndexedDbSave)]
    pub(crate) fn indexed_db_save(
        name: &str,
        bytes: &Uint8Array,
        expected_revision: f64,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraIndexedDbDelete)]
    pub(crate) fn indexed_db_delete(name: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraBrowserLifecycleStatus)]
    pub(crate) fn browser_lifecycle_status() -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraRequestPersistentStorage)]
    pub(crate) fn request_persistent_storage() -> Result<Promise, JsValue>;
}
