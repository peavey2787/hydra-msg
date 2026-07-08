use hydra_app_core::{VaultIdentitySummary, VaultSessionStatus};

use super::scalar::{option_u64_json, string_list_json};
use crate::gui::encoding::json_escape;

pub(crate) fn identity_json(identity: &VaultIdentitySummary) -> String {
    format!(
        concat!(
            "{{",
            "\"id\":\"{}\",",
            "\"label\":\"{}\",",
            "\"filename\":\"{}\",",
            "\"fingerprint\":\"{}\",",
            "\"device_id\":\"{}\",",
            "\"device_fingerprint\":\"{}\",",
            "\"generation\":{},",
            "\"revoked\":{},",
            "\"active\":{}",
            "}}"
        ),
        json_escape(&identity.id),
        json_escape(&identity.label),
        json_escape(&identity.filename),
        json_escape(&identity.identity_fingerprint_hex),
        json_escape(&identity.device_id_hex),
        json_escape(&identity.device_fingerprint_hex),
        identity.generation,
        identity.revoked,
        identity.active,
    )
}

pub(crate) fn identity_created_with_session_json(
    identity: &VaultIdentitySummary,
    status: &VaultSessionStatus,
    message: &str,
) -> String {
    format!(
        "{{\"ok\":true,\"message\":\"{}\",\"identity\":{},\"session\":{}}}",
        json_escape(message),
        identity_json(identity),
        session_status_json(status),
    )
}

pub(crate) fn session_status_json(status: &VaultSessionStatus) -> String {
    format!(
        concat!(
            "{{",
            "\"unlocked\":{},",
            "\"unlocked_identity_count\":{},",
            "\"active_identity_unlocked\":{},",
            "\"idle_timeout_seconds\":{},",
            "\"remember_expires_at_ms\":{},",
            "\"unlocked_identity_ids\":[{}]",
            "}}"
        ),
        status.unlocked,
        status.unlocked_identity_count,
        status.active_identity_unlocked,
        option_u64_json(status.idle_timeout_seconds),
        option_u64_json(status.remember_expires_at_ms),
        string_list_json(&status.unlocked_identity_ids),
    )
}
