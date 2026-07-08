use hydra_app_core::{
    RecoveryBackupExportSummary, RecoveryBackupInspection, RecoveryKeyPolicy, StorageRecoveryStatus,
};

use super::scalar::{option_u64_json, option_usize_json, optional_string_json};
use crate::gui::encoding::json_escape;

pub(crate) fn storage_recovery_status_json(status: &StorageRecoveryStatus) -> String {
    format!(
        concat!(
            "{{",
            "\"data_dir\":\"{}\",",
            "\"identity_count\":{},",
            "\"active_identity_id\":{},",
            "\"active_identity_label\":{},",
            "\"message_store_present\":{},",
            "\"message_store_conversation_count\":{},",
            "\"message_store_message_count\":{},",
            "\"live_state_present\":{},",
            "\"live_state_sequence\":{},",
            "\"signed_history_present\":{},",
            "\"signed_history_checkpoint_count\":{},",
            "\"newest_signed_checkpoint_sequence\":{},",
            "\"possible_rollback\":{},",
            "\"rollback_warning\":{},",
            "\"status_message\":\"{}\"",
            "}}"
        ),
        json_escape(&status.data_dir.display().to_string()),
        status.identity_count,
        optional_string_json(status.active_identity_id.as_deref()),
        optional_string_json(status.active_identity_label.as_deref()),
        status.message_store_present,
        option_usize_json(status.message_store_conversation_count),
        option_usize_json(status.message_store_message_count),
        status.live_state_present,
        option_u64_json(status.live_state_sequence),
        status.signed_history_present,
        status.signed_history_checkpoint_count,
        option_u64_json(status.newest_signed_checkpoint_sequence),
        status.possible_rollback,
        optional_string_json(status.rollback_warning),
        json_escape(&status.status_message),
    )
}

pub(crate) fn recovery_backup_export_json(summary: &RecoveryBackupExportSummary) -> String {
    format!(
        concat!(
            "{{",
            "\"output_path\":\"{}\",",
            "\"bytes_written\":{},",
            "\"key_policy\":\"{}\",",
            "\"allow_active_device_clone\":{},",
            "\"includes_identity\":{},",
            "\"includes_conversations\":{},",
            "\"conversation_count\":{},",
            "\"message_count\":{},",
            "\"pending_commit_count\":{},",
            "\"replay_cursor_count\":{}",
            "}}"
        ),
        json_escape(&summary.output_path.display().to_string()),
        summary.bytes_written,
        recovery_key_policy_label(summary.key_policy),
        summary.allow_active_device_clone,
        summary.includes_identity,
        summary.includes_conversations,
        summary.conversation_count,
        summary.message_count,
        summary.pending_commit_count,
        summary.replay_cursor_count,
    )
}

pub(crate) fn recovery_backup_inspection_json(inspection: &RecoveryBackupInspection) -> String {
    format!(
        concat!(
            "{{",
            "\"key_policy\":\"{}\",",
            "\"allow_active_device_clone\":{},",
            "\"source_device_revoked\":{},",
            "\"includes_identity\":{},",
            "\"includes_conversations\":{},",
            "\"conversation_count\":{},",
            "\"message_count\":{},",
            "\"pending_commit_count\":{},",
            "\"replay_cursor_count\":{}",
            "}}"
        ),
        recovery_key_policy_label(inspection.key_policy),
        inspection.allow_active_device_clone,
        inspection.source_device_revoked,
        inspection.includes_identity,
        inspection.includes_conversations,
        inspection.conversation_count,
        inspection.message_count,
        inspection.pending_commit_count,
        inspection.replay_cursor_count,
    )
}

pub(crate) fn signed_checkpoint_export_json(
    summary: &hydra_app_core::SignedCheckpointExportSummary,
) -> String {
    format!(
        concat!(
            "{{",
            "\"local_history_path\":\"{}\",",
            "\"exported_checkpoint_path\":\"{}\",",
            "\"backup_sequence\":{},",
            "\"local_rollback_counter\":{}",
            "}}"
        ),
        json_escape(&summary.local_history_path.display().to_string()),
        json_escape(&summary.exported_checkpoint_path.display().to_string()),
        summary.backup_sequence,
        summary.local_rollback_counter,
    )
}

pub(crate) fn recovery_key_policy_label(policy: RecoveryKeyPolicy) -> &'static str {
    match policy {
        RecoveryKeyPolicy::UserPassphrase => "user-passphrase",
        RecoveryKeyPolicy::RandomRecoveryKey => "random-recovery-key",
    }
}
