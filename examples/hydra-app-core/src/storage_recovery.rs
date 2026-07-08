use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    export_recovery_backup, inspect_recovery_backup, read_signed_checkpoint_history, AppError,
    AppResult, BackupSecret, EncryptedRecoveryBackup, IdentityVault, LiveStateStore, MessageStore,
    RecoveryBackupOptions, RecoveryKeyPolicy, RecoveryManifest, POSSIBLE_ROLLBACK_WARNING,
};

pub const MESSAGE_STORE_FILE: &str = "messages.db";
pub const LIVE_STATE_FILE: &str = "live-state.db";
pub const SIGNED_BACKUP_HISTORY_FILE: &str = "signed-backup-history.txt";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageRecoveryStatus {
    pub data_dir: PathBuf,
    pub identity_count: usize,
    pub active_identity_id: Option<String>,
    pub active_identity_label: Option<String>,
    pub message_store_present: bool,
    pub message_store_conversation_count: Option<usize>,
    pub message_store_message_count: Option<usize>,
    pub live_state_present: bool,
    pub live_state_sequence: Option<u64>,
    pub signed_history_present: bool,
    pub signed_history_checkpoint_count: usize,
    pub newest_signed_checkpoint_sequence: Option<u64>,
    pub possible_rollback: bool,
    pub rollback_warning: Option<&'static str>,
    pub status_message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBackupExportSummary {
    pub output_path: PathBuf,
    pub bytes_written: usize,
    pub key_policy: RecoveryKeyPolicy,
    pub allow_active_device_clone: bool,
    pub includes_identity: bool,
    pub includes_conversations: bool,
    pub conversation_count: u32,
    pub message_count: u32,
    pub pending_commit_count: u32,
    pub replay_cursor_count: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ActiveIdentityRecoveryBackupExport<'a> {
    pub data_dir: &'a Path,
    pub identity_id: Option<&'a str>,
    pub identity_password: &'a [u8],
    pub storage_password: &'a [u8],
    pub backup_password: &'a [u8],
    pub output_path: &'a Path,
    pub options: RecoveryBackupOptions,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryBackupInspection {
    pub key_policy: RecoveryKeyPolicy,
    pub allow_active_device_clone: bool,
    pub source_device_revoked: bool,
    pub includes_identity: bool,
    pub includes_conversations: bool,
    pub conversation_count: u32,
    pub message_count: u32,
    pub pending_commit_count: u32,
    pub replay_cursor_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpointExportSummary {
    pub local_history_path: PathBuf,
    pub exported_checkpoint_path: PathBuf,
    pub backup_sequence: u64,
    pub local_rollback_counter: u64,
}

pub fn storage_recovery_status(
    data_dir: impl AsRef<Path>,
    storage_password: Option<&[u8]>,
    exported_checkpoint_paths: &[PathBuf],
) -> AppResult<StorageRecoveryStatus> {
    let data_dir = data_dir.as_ref().to_path_buf();
    let vault = IdentityVault::open(&data_dir)?;
    let identities = vault.identities();
    let active = identities.iter().find(|identity| identity.active);
    let message_store_path = data_dir.join(MESSAGE_STORE_FILE);
    let live_state_path = data_dir.join(LIVE_STATE_FILE);
    let history_path = data_dir.join(SIGNED_BACKUP_HISTORY_FILE);
    let history = read_signed_checkpoint_history(&history_path)?;
    let newest_signed_checkpoint_sequence = history
        .iter()
        .map(|checkpoint| checkpoint.backup_sequence)
        .max();

    let mut status_message = "storage status loaded".to_owned();
    let (message_store_conversation_count, message_store_message_count) = if message_store_path
        .exists()
    {
        match storage_password {
            Some(password) => match MessageStore::load(&message_store_path, password) {
                Ok(store) => (
                    Some(store.conversations().len()),
                    Some(store.messages().len()),
                ),
                Err(error) => {
                    status_message = format!("message store locked or unreadable: {error}");
                    (None, None)
                }
            },
            None => {
                status_message = "storage password unavailable for message store status".to_owned();
                (None, None)
            }
        }
    } else {
        (Some(0), Some(0))
    };

    let mut live_state_sequence = None;
    let mut possible_rollback = false;
    let mut rollback_warning = None;
    if live_state_path.exists() {
        match storage_password {
            Some(password) => match LiveStateStore::load_with_signed_backup_history(
                &live_state_path,
                password,
                &history_path,
                exported_checkpoint_paths,
            ) {
                Ok(store) => live_state_sequence = Some(store.rollback_counter()),
                Err(error) if error.to_string().contains(POSSIBLE_ROLLBACK_WARNING) => {
                    possible_rollback = true;
                    rollback_warning = Some(POSSIBLE_ROLLBACK_WARNING);
                    status_message =
                        "possible rollback detected; refusing automatic use".to_owned();
                }
                Err(error) => {
                    status_message = format!("live state locked or unreadable: {error}");
                }
            },
            None => {
                status_message = "storage password unavailable for live-state status".to_owned();
            }
        }
    }

    Ok(StorageRecoveryStatus {
        data_dir,
        identity_count: identities.len(),
        active_identity_id: active.map(|identity| identity.id.clone()),
        active_identity_label: active.map(|identity| identity.label.clone()),
        message_store_present: message_store_path.exists(),
        message_store_conversation_count,
        message_store_message_count,
        live_state_present: live_state_path.exists(),
        live_state_sequence,
        signed_history_present: history_path.exists(),
        signed_history_checkpoint_count: history.len(),
        newest_signed_checkpoint_sequence,
        possible_rollback,
        rollback_warning,
        status_message,
    })
}

pub fn export_active_identity_recovery_backup(
    request: ActiveIdentityRecoveryBackupExport<'_>,
) -> AppResult<RecoveryBackupExportSummary> {
    if request.backup_password.is_empty() {
        return Err(AppError::InvalidInput("backup password must not be empty"));
    }
    let vault = IdentityVault::open(request.data_dir)?;
    let active_id = request
        .identity_id
        .or_else(|| vault.active_identity_id())
        .ok_or(AppError::InvalidState("no active identity selected"))?;
    let identity_store = vault.load_identity_store(active_id, request.identity_password)?;
    let message_store_path = request.data_dir.join(MESSAGE_STORE_FILE);
    let message_store = if request.options.include_conversations && message_store_path.exists() {
        Some(MessageStore::load(
            &message_store_path,
            request.storage_password,
        )?)
    } else {
        None
    };
    let backup = export_recovery_backup(
        &identity_store,
        message_store.as_ref(),
        BackupSecret::Passphrase(request.backup_password),
        request.options,
        request.created_at_ms,
    )?;
    backup.write_to_file(request.output_path)?;
    let manifest =
        inspect_recovery_backup(&backup, BackupSecret::Passphrase(request.backup_password))?;
    Ok(export_summary_from_manifest(
        request.output_path.to_path_buf(),
        backup.as_bytes().len(),
        &manifest,
    ))
}

pub fn inspect_recovery_backup_file(
    backup_path: impl AsRef<Path>,
    backup_password: &[u8],
) -> AppResult<RecoveryBackupInspection> {
    if backup_password.is_empty() {
        return Err(AppError::InvalidInput("backup password must not be empty"));
    }
    let backup = EncryptedRecoveryBackup::read_from_file(backup_path)?;
    let manifest = inspect_recovery_backup(&backup, BackupSecret::Passphrase(backup_password))?;
    Ok(RecoveryBackupInspection {
        key_policy: manifest.key_policy,
        allow_active_device_clone: manifest.allow_active_device_clone,
        source_device_revoked: manifest.source_device_revoked,
        includes_identity: manifest.includes_identity,
        includes_conversations: manifest.includes_conversations,
        conversation_count: manifest.conversation_count,
        message_count: manifest.message_count,
        pending_commit_count: manifest.pending_commit_count,
        replay_cursor_count: manifest.replay_cursor_count,
    })
}

pub fn export_signed_backup_checkpoint_for_active_identity(
    data_dir: impl AsRef<Path>,
    identity_id: Option<&str>,
    identity_password: &[u8],
    storage_password: &[u8],
    export_dir: impl AsRef<Path>,
) -> AppResult<SignedCheckpointExportSummary> {
    let data_dir = data_dir.as_ref();
    let export_dir = export_dir.as_ref();
    let vault = IdentityVault::open(data_dir)?;
    let active_id = identity_id
        .or_else(|| vault.active_identity_id())
        .ok_or(AppError::InvalidState("no active identity selected"))?;
    let identity_store = vault.load_identity_store(active_id, identity_password)?;
    let identity = identity_store.identity()?;
    let live_state_path = data_dir.join(LIVE_STATE_FILE);
    let history_path = data_dir.join(SIGNED_BACKUP_HISTORY_FILE);
    let mut live_state = if live_state_path.exists() {
        LiveStateStore::load(&live_state_path, storage_password)?
    } else {
        LiveStateStore::create(&live_state_path, storage_password)?
    };
    let checkpoint = live_state.save_with_signed_backup_history(
        storage_password,
        identity,
        &history_path,
        Some(export_dir),
    )?;
    let exported_checkpoint_path = export_dir.join(format!(
        "hydra-checkpoint-{:020}.hcpt",
        checkpoint.backup_sequence,
    ));
    Ok(SignedCheckpointExportSummary {
        local_history_path: history_path,
        exported_checkpoint_path,
        backup_sequence: checkpoint.backup_sequence,
        local_rollback_counter: checkpoint.local_rollback_counter,
    })
}

pub fn check_signed_backup_history(
    data_dir: impl AsRef<Path>,
    storage_password: &[u8],
    exported_checkpoint_paths: &[PathBuf],
) -> AppResult<StorageRecoveryStatus> {
    storage_recovery_status(data_dir, Some(storage_password), exported_checkpoint_paths)
}

#[must_use]
pub fn current_recovery_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn export_summary_from_manifest(
    output_path: PathBuf,
    bytes_written: usize,
    manifest: &RecoveryManifest,
) -> RecoveryBackupExportSummary {
    RecoveryBackupExportSummary {
        output_path,
        bytes_written,
        key_policy: manifest.key_policy,
        allow_active_device_clone: manifest.allow_active_device_clone,
        includes_identity: manifest.includes_identity,
        includes_conversations: manifest.includes_conversations,
        conversation_count: manifest.conversation_count,
        message_count: manifest.message_count,
        pending_commit_count: manifest.pending_commit_count,
        replay_cursor_count: manifest.replay_cursor_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("hydra-storage-recovery-{label}-{unique}"))
    }

    #[test]
    fn encrypted_recovery_backup_exports_and_inspects_without_cloning_by_default() {
        let data_dir = temp_dir("backup");
        let mut vault = IdentityVault::open(&data_dir).unwrap();
        let identity = vault
            .create_identity("alice", b"identity password")
            .unwrap();
        let message_path = data_dir.join(MESSAGE_STORE_FILE);
        let _ = MessageStore::create(&message_path, b"storage password").unwrap();
        let output = data_dir.join("exports").join("alice.hydra-backup");
        let summary = export_active_identity_recovery_backup(ActiveIdentityRecoveryBackupExport {
            data_dir: &data_dir,
            identity_id: Some(&identity.id),
            identity_password: b"identity password",
            storage_password: b"storage password",
            backup_password: b"backup password",
            output_path: &output,
            options: RecoveryBackupOptions::default(),
            created_at_ms: 1,
        })
        .unwrap();
        assert!(output.exists());
        assert!(summary.includes_identity);
        assert!(summary.includes_conversations);
        assert!(!summary.allow_active_device_clone);
        let inspected = inspect_recovery_backup_file(&output, b"backup password").unwrap();
        assert!(inspected.includes_identity);
        assert!(inspected.includes_conversations);
        assert!(!inspected.allow_active_device_clone);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn signed_checkpoint_status_reports_possible_rollback_without_override() {
        let data_dir = temp_dir("rollback");
        let mut vault = IdentityVault::open(&data_dir).unwrap();
        let identity = vault
            .create_identity("alice", b"identity password")
            .unwrap();
        let export_dir = data_dir.join("checkpoints");
        let first = export_signed_backup_checkpoint_for_active_identity(
            &data_dir,
            Some(&identity.id),
            b"identity password",
            b"storage password",
            &export_dir,
        )
        .unwrap();
        assert_eq!(first.backup_sequence, 1);
        let live_state = data_dir.join(LIVE_STATE_FILE);
        let checkpoint = live_state.with_extension("db.checkpoint");
        let rollback_log = live_state.with_extension("db.rollback.log");
        let rollback_mirror = live_state.with_extension("db.rollback.mirror.log");
        let stale_state = data_dir.join("live-state.db.hydra-stale");
        let stale_checkpoint = data_dir.join("live-state.checkpoint.hydra-stale");
        let stale_rollback_log = data_dir.join("live-state.rollback-log.hydra-stale");
        let stale_rollback_mirror = data_dir.join("live-state.rollback-mirror.hydra-stale");
        std::fs::copy(&live_state, &stale_state).unwrap();
        std::fs::copy(&checkpoint, &stale_checkpoint).unwrap();
        std::fs::copy(&rollback_log, &stale_rollback_log).unwrap();
        std::fs::copy(&rollback_mirror, &stale_rollback_mirror).unwrap();
        let second = export_signed_backup_checkpoint_for_active_identity(
            &data_dir,
            Some(&identity.id),
            b"identity password",
            b"storage password",
            &export_dir,
        )
        .unwrap();
        assert_eq!(second.backup_sequence, 2);
        std::fs::copy(stale_state, &live_state).unwrap();
        std::fs::copy(stale_checkpoint, &checkpoint).unwrap();
        std::fs::copy(stale_rollback_log, &rollback_log).unwrap();
        std::fs::copy(stale_rollback_mirror, &rollback_mirror).unwrap();
        let status = check_signed_backup_history(
            &data_dir,
            b"storage password",
            std::slice::from_ref(&export_dir),
        )
        .unwrap();
        assert!(status.possible_rollback);
        assert_eq!(status.rollback_warning, Some(POSSIBLE_ROLLBACK_WARNING));
        let _ = std::fs::remove_dir_all(data_dir);
    }
}
