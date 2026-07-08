use hydra_app_core::{storage_recovery_status, IdentityVault};

use crate::{config::AppConfig, contacts::ContactBook, secrets::load_storage_secret};

use super::json::{
    chat_state_json, contact_record_json, identity_json, option_u64_json,
    storage_recovery_status_json, string_list_json,
};
use crate::gui::{
    encoding::json_escape,
    state::{message_stats, GuiAppState},
};

pub(crate) fn api_state(app_state: &GuiAppState) -> Result<String, String> {
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let identities = vault.identities();
    let first_run_required = identities.is_empty();
    let active_identity = identities
        .iter()
        .find(|identity| identity.active)
        .map(|identity| identity.label.as_str())
        .unwrap_or("");
    let session_status = app_state.lock_identity_session()?.status(&vault);
    let secret = load_storage_secret(&config.data_dir)?;
    let contacts = ContactBook::load(&config.data_dir, secret.expose_secret())?;
    let data_dir = config.data_dir.display().to_string();
    let identity_present = !first_run_required;
    let message_path = config.data_dir.join("messages.db");
    let secret_source = load_storage_secret(&config.data_dir)
        .map(|secret| secret.source_label().to_owned())
        .unwrap_or_else(|error| format!("unavailable: {error}"));
    let message_stats = message_stats(&message_path, &config.data_dir);
    let identity_json = identities
        .iter()
        .map(identity_json)
        .collect::<Vec<_>>()
        .join(",");
    let contact_records = contacts.contacts();
    let contact_json = contact_records
        .iter()
        .map(contact_record_json)
        .collect::<Vec<_>>()
        .join(",");
    let recovery_status =
        storage_recovery_status(&config.data_dir, Some(secret.expose_secret()), &[])
            .map_err(|error| error.to_string())?;
    let (chat_shell_status, chat_json) = if recovery_status.possible_rollback {
        (
            "blocked: possible rollback detected".to_owned(),
            String::new(),
        )
    } else {
        chat_state_json(&config, &contact_records)
    };
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"data_dir\":\"{}\",",
            "\"first_run_required\":{},",
            "\"identity_present\":{},",
            "\"identity_count\":{},",
            "\"active_identity_label\":\"{}\",",
            "\"identity_session_unlocked\":{},",
            "\"unlocked_identity_count\":{},",
            "\"active_identity_unlocked\":{},",
            "\"idle_timeout_seconds\":{},",
            "\"remember_expires_at_ms\":{},",
            "\"unlocked_identity_ids\":[{}],",
            "\"identities\":[{}],",
            "\"message_db_present\":{},",
            "\"conversation_count\":{},",
            "\"message_count\":{},",
            "\"message_db_status\":\"{}\",",
            "\"storage_secret_source\":\"{}\",",
            "\"direct_rekey_every_messages\":{},",
            "\"group_lite_rekey_every_messages\":{},",
            "\"group_interactive_rekey_every_messages\":{},",
            "\"group_broadcast_rekey_every_messages\":{},",
            "\"group_rekey_on_membership_change\":{},",
            "\"rotate_identity_after_rekey_count\":{},",
            "\"incoming_message_policy\":\"{}\",",
            "\"default_group_max_members\":{},",
            "\"default_chat_list_mode\":\"{}\",",
            "\"chat_whitelist\":[{}],",
            "\"chat_blacklist\":[{}],",
            "\"contacts\":[{}],",
            "\"chat_shell_status\":\"{}\",",
            "\"chats\":[{}],",
            "\"recovery_status\":{}",
            "}}"
        ),
        json_escape(&data_dir),
        first_run_required,
        identity_present,
        identities.len(),
        json_escape(active_identity),
        session_status.unlocked,
        session_status.unlocked_identity_count,
        session_status.active_identity_unlocked,
        option_u64_json(session_status.idle_timeout_seconds),
        option_u64_json(session_status.remember_expires_at_ms),
        string_list_json(&session_status.unlocked_identity_ids),
        identity_json,
        message_path.exists(),
        message_stats.conversations,
        message_stats.messages,
        json_escape(&message_stats.status),
        json_escape(&secret_source),
        config.rekey.direct_every_messages,
        config.rekey.group_lite_every_messages,
        config.rekey.group_interactive_every_messages,
        config.rekey.group_broadcast_every_messages,
        config.rekey.group_on_membership_change,
        config.rekey.rotate_identity_after_rekey_count,
        json_escape(config.chat.incoming_message_policy.as_str()),
        config.chat.default_group_max_members,
        json_escape(config.chat.default_chat_list_mode.as_str()),
        string_list_json(&config.chat.whitelist),
        string_list_json(&config.chat.blacklist),
        contact_json,
        json_escape(&chat_shell_status),
        chat_json,
        storage_recovery_status_json(&recovery_status),
    ))
}
