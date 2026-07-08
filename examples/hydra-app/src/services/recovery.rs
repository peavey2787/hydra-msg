use std::path::{Path, PathBuf};

use hydra_app_core::{
    check_signed_backup_history, current_recovery_time_ms, export_active_identity_recovery_backup,
    export_signed_backup_checkpoint_for_active_identity, inspect_recovery_backup_file,
    storage_recovery_status, ActiveIdentityRecoveryBackupExport, RecoveryBackupExportSummary,
    RecoveryBackupInspection, RecoveryBackupOptions, SignedCheckpointExportSummary,
    StorageRecoveryStatus,
};

use super::context::AppContext;

pub fn recovery_status(exported_paths: &[PathBuf]) -> Result<StorageRecoveryStatus, String> {
    let context = AppContext::load()?;
    storage_recovery_status(
        &context.config.data_dir,
        Some(context.storage_secret()),
        exported_paths,
    )
    .map_err(|error| error.to_string())
}

pub fn export_recovery_backup_for_active_identity(
    identity_password: &[u8],
    backup_password: &[u8],
    output_path: impl AsRef<Path>,
    allow_active_device_clone: bool,
) -> Result<RecoveryBackupExportSummary, String> {
    let context = AppContext::load()?;
    export_active_identity_recovery_backup(ActiveIdentityRecoveryBackupExport {
        data_dir: &context.config.data_dir,
        identity_id: None,
        identity_password,
        storage_password: context.storage_secret(),
        backup_password,
        output_path: output_path.as_ref(),
        options: RecoveryBackupOptions {
            allow_active_device_clone,
            include_conversations: true,
        },
        created_at_ms: current_recovery_time_ms(),
    })
    .map_err(|error| error.to_string())
}

pub fn inspect_recovery_backup(
    backup_path: impl AsRef<Path>,
    backup_password: &[u8],
) -> Result<RecoveryBackupInspection, String> {
    inspect_recovery_backup_file(backup_path, backup_password).map_err(|error| error.to_string())
}

pub fn export_signed_checkpoint_for_active_identity(
    identity_password: &[u8],
    export_dir: impl AsRef<Path>,
) -> Result<SignedCheckpointExportSummary, String> {
    let context = AppContext::load()?;
    export_signed_backup_checkpoint_for_active_identity(
        &context.config.data_dir,
        None,
        identity_password,
        context.storage_secret(),
        export_dir,
    )
    .map_err(|error| error.to_string())
}

pub fn check_signed_history(exported_paths: &[PathBuf]) -> Result<StorageRecoveryStatus, String> {
    let context = AppContext::load()?;
    check_signed_backup_history(
        &context.config.data_dir,
        context.storage_secret(),
        exported_paths,
    )
    .map_err(|error| error.to_string())
}
