use hydra_app_core::{ChatConversationSummary, ChatMessageSummary, ChatShell};

use crate::gui::encoding::json_escape;
use crate::{config::AppConfig, contacts::ContactRecord, secrets::load_storage_secret};

pub(crate) fn chat_state_json(config: &AppConfig, contacts: &[ContactRecord]) -> (String, String) {
    let path = config.data_dir.join("messages.db");
    if !path.exists() {
        return ("not created yet".to_owned(), String::new());
    }
    let secret = match load_storage_secret(&config.data_dir) {
        Ok(secret) => secret,
        Err(error) => {
            return (
                format!("storage secret unavailable: {error}"),
                String::new(),
            )
        }
    };
    match ChatShell::open_or_create(&path, secret.expose_secret()) {
        Ok(shell) => {
            let chats = shell
                .conversations()
                .iter()
                .map(|conversation| chat_conversation_json(conversation, &shell, contacts))
                .collect::<Vec<_>>()
                .join(",");
            ("loaded".to_owned(), chats)
        }
        Err(error) => (
            format!("locked or unreadable: {:?}", error.class()),
            String::new(),
        ),
    }
}

pub(crate) fn chat_conversation_json(
    conversation: &ChatConversationSummary,
    shell: &ChatShell,
    contacts: &[ContactRecord],
) -> String {
    let messages = shell
        .messages_for(&conversation.id_hex)
        .map(|messages| {
            messages
                .iter()
                .map(chat_message_json)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let title = chat_title(conversation, contacts);
    let members = conversation
        .member_fingerprints_hex
        .iter()
        .map(|fingerprint| format!("\"{}\"", json_escape(fingerprint)))
        .collect::<Vec<_>>()
        .join(",");
    let last_direction = conversation
        .last_message_direction
        .map(|direction| format!("\"{}\"", hydra_app_core::message_direction_label(direction)))
        .unwrap_or_else(|| "null".to_owned());
    let last_at = conversation
        .last_message_at_ms
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    format!(
        concat!(
            "{{",
            "\"id\":\"{}\",",
            "\"title\":\"{}\",",
            "\"kind\":\"{}\",",
            "\"created_at_ms\":{},",
            "\"current_epoch\":{},",
            "\"current_state_version\":{},",
            "\"members\":[{}],",
            "\"message_count\":{},",
            "\"last_message_preview\":\"{}\",",
            "\"last_message_direction\":{},",
            "\"last_message_at_ms\":{},",
            "\"messages\":[{}]",
            "}}"
        ),
        json_escape(&conversation.id_hex),
        json_escape(&title),
        json_escape(conversation.kind_label),
        conversation.created_at_ms,
        conversation.current_epoch,
        conversation.current_state_version,
        members,
        conversation.message_count,
        json_escape(&conversation.last_message_preview),
        last_direction,
        last_at,
        messages,
    )
}

pub(crate) fn chat_message_json(message: &ChatMessageSummary) -> String {
    format!(
        concat!(
            "{{",
            "\"conversation_id\":\"{}\",",
            "\"direction\":\"{}\",",
            "\"sender_id\":\"{}\",",
            "\"epoch\":{},",
            "\"state_version\":{},",
            "\"message_index\":{},",
            "\"received_at_ms\":{},",
            "\"content_preview\":\"{}\"",
            "}}"
        ),
        json_escape(&message.conversation_id_hex),
        json_escape(message.direction_label),
        json_escape(&message.sender_id_hex),
        message.epoch,
        message.state_version,
        message.message_index,
        message.received_at_ms,
        json_escape(&message.content_preview),
    )
}

pub(crate) fn chat_title(
    conversation: &ChatConversationSummary,
    contacts: &[ContactRecord],
) -> String {
    if conversation.kind_label == "direct" {
        for fingerprint in &conversation.member_fingerprints_hex {
            if let Some(contact) = contacts
                .iter()
                .find(|contact| &contact.fingerprint_hex == fingerprint)
            {
                return contact.alias.clone();
            }
        }
        return "Direct chat".to_owned();
    }
    conversation.kind_label.replace('-', " ")
}
