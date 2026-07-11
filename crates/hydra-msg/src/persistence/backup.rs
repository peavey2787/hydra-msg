//! Backup portability boundary.
//!
//! Backups are the explicit user-controlled export/import format. They share
//! the canonical plaintext snapshot validation path with local persistence, but
//! they are not a platform storage adapter and must not be used as hidden app
//! state.

use crate::{persistence::encrypted_snapshot, Hydra, HydraResult};

pub(crate) fn export_verified_backup_snapshot(
    snapshot: &[u8],
    password: &str,
) -> HydraResult<Vec<u8>> {
    Hydra::verify_state_snapshot(snapshot)?;
    encrypted_snapshot::encode_backup_snapshot(snapshot, password)
}

pub(crate) fn open_verified_backup_snapshot(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let snapshot = encrypted_snapshot::decode_backup_snapshot(bytes, password)?;
    Hydra::verify_state_snapshot(&snapshot)?;
    Ok(snapshot)
}
