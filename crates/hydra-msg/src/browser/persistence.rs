//! WASM/browser persistence adapter boundary.
//!
//! This module owns the Rust facade for browser storage. The IndexedDB
//! transaction implementation lives in `persistence_js.rs`; both layers store
//! only opaque encrypted HYDRA snapshot bytes.

use crate::{
    browser_persistence_js::{
        browser_lifecycle_status, indexed_db_delete, indexed_db_load, indexed_db_save,
        request_persistent_storage,
    },
    HydraMsgError, HydraResult,
};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

const MAX_PERSISTENT_NAME_BYTES: usize = 256;

pub(crate) struct PersistentSnapshot {
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) revision: u64,
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
