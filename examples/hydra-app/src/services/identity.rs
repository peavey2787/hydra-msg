use std::path::Path;

use hydra_app_core::{
    contact_hex_encode, IdentityImportPolicy, UnlockedIdentityPublicMaterial, VaultIdentitySummary,
};

use super::context::AppContext;

pub fn list_identities() -> Result<Vec<VaultIdentitySummary>, String> {
    AppContext::load()?.vault().map(|vault| vault.identities())
}

pub fn generate_identity(label: &str, password: &[u8]) -> Result<VaultIdentitySummary, String> {
    let context = AppContext::load()?;
    let mut vault = context.vault()?;
    vault
        .create_identity(label, password)
        .map_err(|error| error.to_string())
}

pub fn import_identity_store_file(
    label: &str,
    source_path: impl AsRef<Path>,
    source_password: &[u8],
    new_password: &[u8],
    preserve_device_id: bool,
) -> Result<VaultIdentitySummary, String> {
    let context = AppContext::load()?;
    let mut vault = context.vault()?;
    vault
        .import_identity_store_file(
            label,
            source_path,
            source_password,
            new_password,
            preserve_device_id,
        )
        .map_err(|error| error.to_string())
}

pub fn import_identity_backup_file(
    label: &str,
    backup_path: impl AsRef<Path>,
    backup_password: &[u8],
    identity_password: &[u8],
    policy: IdentityImportPolicy,
) -> Result<VaultIdentitySummary, String> {
    let context = AppContext::load()?;
    let mut vault = context.vault()?;
    vault
        .import_recovery_backup_file(
            label,
            backup_path,
            backup_password,
            identity_password,
            policy,
        )
        .map_err(|error| error.to_string())
}

pub fn switch_identity(id: &str) -> Result<VaultIdentitySummary, String> {
    let context = AppContext::load()?;
    let mut vault = context.vault()?;
    vault
        .switch_active_identity(id)
        .map_err(|error| error.to_string())
}

pub fn active_identity_public_material(
    identity_password: &[u8],
) -> Result<UnlockedIdentityPublicMaterial, String> {
    let context = AppContext::load()?;
    let vault = context.vault()?;
    let active_id = vault
        .active_identity_id()
        .ok_or_else(|| "no active identity selected".to_owned())?;
    let active = vault
        .identities()
        .into_iter()
        .find(|identity| identity.id == active_id)
        .ok_or_else(|| "active identity metadata is missing".to_owned())?;
    let store = vault
        .load_identity_store(active_id, identity_password)
        .map_err(|error| error.to_string())?;
    let public = store.public_identity();
    Ok(UnlockedIdentityPublicMaterial {
        id: active.id,
        label: active.label,
        public_key_hex: contact_hex_encode(&public.public_key().0),
        identity_fingerprint_hex: contact_hex_encode(&public.fingerprint().0),
        device_id_hex: active.device_id_hex,
        device_fingerprint_hex: active.device_fingerprint_hex,
    })
}
