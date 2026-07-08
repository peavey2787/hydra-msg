use crate::services;
use crate::{config::AppConfig, contacts::ContactBook, secrets::load_storage_secret};
use hydra_app_core::{
    contact_hex_encode, conversation_kind_from_label, current_chat_bootstrap_time_ms, ChatShell,
};

use super::support::require_active_identity_unlocked;
use crate::gui::{
    encoding::json_escape,
    forms::{parse_form, required_form_value},
    state::GuiAppState,
};

pub(crate) fn api_chat_create_direct(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    require_active_identity_unlocked(app_state)?;
    let form = parse_form(body)?;
    let alias = required_form_value(&form, "alias")?;
    let config = AppConfig::load_or_default()?;
    let secret = load_storage_secret(&config.data_dir)?;
    let contacts = ContactBook::load(&config.data_dir, secret.expose_secret())?;
    let contact_records = contacts.contacts();
    let contact = contact_records
        .iter()
        .find(|contact| contact.alias == alias)
        .ok_or_else(|| "trusted contact alias does not exist".to_owned())?;
    let mut shell =
        ChatShell::open_or_create(config.data_dir.join("messages.db"), secret.expose_secret())
            .map_err(|error| error.to_string())?;
    let conversation_id = shell
        .create_direct_conversation(&contact.fingerprint_hex, current_chat_bootstrap_time_ms())
        .map_err(|error| error.to_string())?;
    shell
        .save(secret.expose_secret())
        .map_err(|error| error.to_string())?;
    let conversation_id_hex = contact_hex_encode(&conversation_id.0);
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"message\":\"direct chat ready\",",
            "\"conversation_id\":\"{}\",",
            "\"max_members\":2,",
            "\"list_policy\":\"direct-contact\"",
            "}}"
        ),
        json_escape(&conversation_id_hex),
    ))
}

pub(crate) fn api_chat_create_group(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    require_active_identity_unlocked(app_state)?;
    let form = parse_form(body)?;
    let kind_label = required_form_value(&form, "kind")?;
    let kind = conversation_kind_from_label(kind_label).map_err(|error| error.to_string())?;
    let options = services::group_start_options(
        form.get("max_members").map(String::as_str),
        form.get("list_policy").map(String::as_str),
    )?;
    let config = AppConfig::load_or_default()?;
    let secret = load_storage_secret(&config.data_dir)?;
    let mut shell =
        ChatShell::open_or_create(config.data_dir.join("messages.db"), secret.expose_secret())
            .map_err(|error| error.to_string())?;
    let conversation_id = shell
        .create_group_conversation(kind, current_chat_bootstrap_time_ms())
        .map_err(|error| error.to_string())?;
    shell
        .save(secret.expose_secret())
        .map_err(|error| error.to_string())?;
    let conversation_id_hex = contact_hex_encode(&conversation_id.0);
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"message\":\"group chat shell ready\",",
            "\"conversation_id\":\"{}\",",
            "\"max_members\":{},",
            "\"list_policy\":\"{}\"",
            "}}"
        ),
        json_escape(&conversation_id_hex),
        options.max_members,
        json_escape(options.list_mode.as_str()),
    ))
}

pub(crate) fn api_chat_send(body: &[u8], app_state: &GuiAppState) -> Result<String, String> {
    let active = require_active_identity_unlocked(app_state)?;
    let form = parse_form(body)?;
    let conversation_id = required_form_value(&form, "conversation_id")?;
    let message = required_form_value(&form, "message")?;
    let config = AppConfig::load_or_default()?;
    let secret = load_storage_secret(&config.data_dir)?;
    let mut shell =
        ChatShell::open_or_create(config.data_dir.join("messages.db"), secret.expose_secret())
            .map_err(|error| error.to_string())?;
    let message_index = shell
        .append_outbound_message(
            conversation_id,
            &active.identity_fingerprint_hex,
            message,
            current_chat_bootstrap_time_ms(),
        )
        .map_err(|error| error.to_string())?;
    shell
        .save(secret.expose_secret())
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"message stored in encrypted local chat database\",\"message_index\":{message_index}}}"
    ))
}

pub(crate) fn api_chat_receive_review(
    body: &[u8],
    app_state: &GuiAppState,
) -> Result<String, String> {
    require_active_identity_unlocked(app_state)?;
    let form = parse_form(body)?;
    let conversation_id = required_form_value(&form, "conversation_id")?;
    let message = required_form_value(&form, "message")?;
    let sender_id = form.get("sender_id_hex").map(String::as_str);
    let message_index =
        services::receive_reviewed_chat_message(conversation_id, sender_id, message)?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"reviewed inbound message stored locally\",\"message_index\":{message_index}}}"
    ))
}
