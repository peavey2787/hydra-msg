//! Internal persistence ownership boundary.
//!
//! The facade keeps the public API in `storage.rs`. This module owns the
//! internal persistence responsibilities: canonical snapshot build/apply,
//! encrypted snapshot sealing/opening, native opaque-byte storage, rollback
//! guards, and status DTOs.

pub(crate) mod backup;
pub(crate) mod encrypted_snapshot;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod native_store;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod rollback;
pub(crate) mod snapshot;
pub(crate) mod status;

pub use self::status::{HydraStorageDebugStatus, HydraStorageStatus};
