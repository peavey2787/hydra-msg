//! WASM/browser persistence adapter boundary.
//!
//! This module owns browser storage mechanics only. IndexedDB stores opaque
//! encrypted HYDRA snapshot bytes keyed by a developer-provided profile name.
//! JavaScript does not parse or mutate HYDRA plaintext, KDF records, identities,
//! contacts, messages, lobbies, or attachment contents.

use crate::{HydraMsgError, HydraResult};
use js_sys::{Array, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const MAX_PERSISTENT_NAME_BYTES: usize = 256;

pub(crate) struct PersistentSnapshot {
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) revision: u64,
}

#[wasm_bindgen(inline_js = r#"
const HYDRA_DB_NAME = 'hydra-msg';
const HYDRA_DB_VERSION = 2;
const HYDRA_STORE_NAME = 'snapshots';
const HYDRA_MAX_NAME_BYTES = 256;
const HYDRA_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;
const HYDRA_ADAPTER_VERSION = 2;

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
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB open failed'));
    request.onblocked = () => reject(new Error('IndexedDB open blocked by another tab'));
  });
}

function transactionDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
    tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction failed'));
  });
}

export async function hydraIndexedDbLoad(name) {
  name = validateHydraSnapshotName(name);
  const db = await openHydraIndexedDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(HYDRA_STORE_NAME, 'readonly');
      const request = tx.objectStore(HYDRA_STORE_NAME).get(name);
      request.onsuccess = () => {
        const record = request.result;
        const result = [];
        if (!record) {
          result[0] = undefined;
          result[1] = 0;
          resolve(result);
          return;
        }
        result[0] = new Uint8Array(record.snapshot);
        result[1] = hydraRecordRevision(record);
        resolve(result);
      };
      request.onerror = () => reject(request.error || tx.error || new Error('IndexedDB read failed'));
      tx.onabort = () => reject(tx.error || new Error('IndexedDB read transaction aborted'));
    });
  } finally {
    db.close();
  }
}

export async function hydraIndexedDbSave(name, bytes, expectedRevision) {
  name = validateHydraSnapshotName(name);
  const snapshot = validateHydraSnapshotBytes(bytes);
  expectedRevision = validateHydraRevision(expectedRevision);
  const db = await openHydraIndexedDb();
  try {
    return await new Promise((resolve, reject) => {
      let settled = false;
      const tx = db.transaction(HYDRA_STORE_NAME, 'readwrite');
      const store = tx.objectStore(HYDRA_STORE_NAME);
      const fail = (error) => {
        if (settled) {
          return;
        }
        settled = true;
        try { tx.abort(); } catch (_) { /* transaction may already be finished */ }
        reject(error);
      };
      const request = store.get(name);
      request.onsuccess = () => {
        try {
          const currentRevision = request.result ? hydraRecordRevision(request.result) : 0;
          if (currentRevision !== expectedRevision) {
            fail(staleHydraProfileError(name, expectedRevision, currentRevision));
            return;
          }
          const nextRevision = currentRevision + 1;
          const putRequest = store.put({
            name,
            snapshot,
            revision: nextRevision,
            adapterVersion: HYDRA_ADAPTER_VERSION
          });
          putRequest.onerror = () => fail(putRequest.error || tx.error || new Error('IndexedDB write failed'));
          tx.oncomplete = () => {
            if (!settled) {
              settled = true;
              resolve(nextRevision);
            }
          };
        } catch (error) {
          fail(error);
        }
      };
      request.onerror = () => fail(request.error || tx.error || new Error('IndexedDB read-before-write failed'));
      tx.onerror = () => fail(tx.error || new Error('IndexedDB transaction failed'));
      tx.onabort = () => {
        if (!settled) {
          settled = true;
          reject(tx.error || new Error('IndexedDB transaction aborted'));
        }
      };
    });
  } finally {
    db.close();
  }
}

export async function hydraIndexedDbDelete(name) {
  name = validateHydraSnapshotName(name);
  const db = await openHydraIndexedDb();
  try {
    const tx = db.transaction(HYDRA_STORE_NAME, 'readwrite');
    tx.objectStore(HYDRA_STORE_NAME).delete(name);
    await transactionDone(tx);
  } finally {
    db.close();
  }
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
    fn indexed_db_load(name: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraIndexedDbSave)]
    fn indexed_db_save(
        name: &str,
        bytes: &Uint8Array,
        expected_revision: f64,
    ) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraIndexedDbDelete)]
    fn indexed_db_delete(name: &str) -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraBrowserLifecycleStatus)]
    fn browser_lifecycle_status() -> Result<Promise, JsValue>;

    #[wasm_bindgen(catch, js_name = hydraRequestPersistentStorage)]
    fn request_persistent_storage() -> Result<Promise, JsValue>;
}

pub(crate) async fn load_encrypted_snapshot(name: &str) -> HydraResult<PersistentSnapshot> {
    validate_snapshot_name(name)?;
    let value = JsFuture::from(indexed_db_load(name).map_err(js_error)?)
        .await
        .map_err(js_error)?;
    let array = Array::from(&value);
    let snapshot = array.get(0);
    let revision = revision_from_js(&array.get(1))?;
    let bytes = if snapshot.is_undefined() || snapshot.is_null() {
        None
    } else {
        Some(Uint8Array::new(&snapshot).to_vec())
    };
    Ok(PersistentSnapshot { bytes, revision })
}

pub(crate) async fn save_encrypted_snapshot(
    name: &str,
    bytes: &[u8],
    expected_revision: u64,
) -> HydraResult<u64> {
    validate_snapshot_name(name)?;
    let array = Uint8Array::from(bytes);
    let value =
        JsFuture::from(indexed_db_save(name, &array, expected_revision as f64).map_err(js_error)?)
            .await
            .map_err(js_error)?;
    revision_from_js(&value)
}

pub(crate) async fn delete_encrypted_snapshot(name: &str) -> HydraResult<()> {
    validate_snapshot_name(name)?;
    JsFuture::from(indexed_db_delete(name).map_err(js_error)?)
        .await
        .map_err(js_error)?;
    Ok(())
}

pub(crate) async fn lifecycle_status_json() -> HydraResult<String> {
    let value = JsFuture::from(browser_lifecycle_status().map_err(js_error)?)
        .await
        .map_err(js_error)?;
    Ok(value.as_string().unwrap_or_else(|| "{}".to_string()))
}

pub(crate) async fn request_persistence() -> HydraResult<bool> {
    let value = JsFuture::from(request_persistent_storage().map_err(js_error)?)
        .await
        .map_err(js_error)?;
    Ok(value.as_bool().unwrap_or(false))
}

fn validate_snapshot_name(name: &str) -> HydraResult<()> {
    if name.is_empty() {
        return Err(HydraMsgError::InvalidInput(
            "HYDRA persistent snapshot name must not be empty",
        ));
    }
    if name.len() > MAX_PERSISTENT_NAME_BYTES {
        return Err(HydraMsgError::InvalidInput(
            "HYDRA persistent snapshot name is too long",
        ));
    }
    Ok(())
}

fn revision_from_js(value: &JsValue) -> HydraResult<u64> {
    let revision = value.as_f64().ok_or(HydraMsgError::InvalidEncoding(
        "HYDRA persistent profile revision is invalid",
    ))?;
    if !revision.is_finite() || revision < 0.0 || revision.fract() != 0.0 {
        return Err(HydraMsgError::InvalidEncoding(
            "HYDRA persistent profile revision is invalid",
        ));
    }
    Ok(revision as u64)
}

fn js_error(value: JsValue) -> HydraMsgError {
    HydraMsgError::Io(
        value
            .as_string()
            .unwrap_or_else(|| format!("HYDRA browser persistence error: {value:?}")),
    )
}
