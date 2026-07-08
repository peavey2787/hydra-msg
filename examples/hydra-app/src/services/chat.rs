use hydra_app_core::{
    contact_hex_encode, conversation_kind_from_label, current_chat_bootstrap_time_ms,
    ChatConversationSummary, ConversationKind,
};

use crate::{
    config::{AppConfig, ChatListMode, IncomingMessagePolicy},
    contacts::ContactRecord,
};

use super::context::AppContext;

pub struct ChatSnapshot {
    pub status: String,
    pub conversations: Vec<ChatConversationSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupStartOptions {
    pub max_members: u16,
    pub list_mode: ChatListMode,
}

pub fn chat_snapshot() -> Result<ChatSnapshot, String> {
    let context = AppContext::load()?;
    let shell = context.chat_shell()?;
    let conversations = shell.conversations();
    Ok(ChatSnapshot {
        status: "ready".to_owned(),
        conversations,
    })
}

pub fn create_direct_chat(alias: &str) -> Result<String, String> {
    let context = AppContext::load()?;
    let contacts = context.contact_book()?;
    let contact_records = contacts.contacts();
    let contact = contact_records
        .iter()
        .find(|contact| contact.alias == alias)
        .ok_or_else(|| "trusted contact alias does not exist".to_owned())?;
    let mut shell = context.chat_shell()?;
    let conversation_id = shell
        .create_direct_conversation(&contact.fingerprint_hex, current_chat_bootstrap_time_ms())
        .map_err(|error| error.to_string())?;
    shell
        .save(context.storage_secret())
        .map_err(|error| error.to_string())?;
    Ok(contact_hex_encode(&conversation_id.0))
}

pub fn create_group_chat(kind: ConversationKind) -> Result<String, String> {
    let context = AppContext::load()?;
    let mut shell = context.chat_shell()?;
    let conversation_id = shell
        .create_group_conversation(kind, current_chat_bootstrap_time_ms())
        .map_err(|error| error.to_string())?;
    shell
        .save(context.storage_secret())
        .map_err(|error| error.to_string())?;
    Ok(contact_hex_encode(&conversation_id.0))
}

pub fn create_group_chat_from_label(kind: &str) -> Result<String, String> {
    create_group_chat(conversation_kind_from_label(kind).map_err(|error| error.to_string())?)
}

pub fn group_start_options(
    max_members: Option<&str>,
    list_mode: Option<&str>,
) -> Result<GroupStartOptions, String> {
    let config = AppConfig::load_or_default()?;
    let max_members = match max_members.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            let mut trial = config.clone();
            trial.set("default_group_max_members", value)?;
            trial.chat.default_group_max_members
        }
        None => config.chat.default_group_max_members,
    };
    let list_mode = match list_mode.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => ChatListMode::parse("start_chat_list_mode", value)?,
        None => config.chat.default_chat_list_mode,
    };
    Ok(GroupStartOptions {
        max_members,
        list_mode,
    })
}

pub fn send_chat_message(
    conversation_id: &str,
    sender_id_hex: &str,
    message: &str,
) -> Result<u64, String> {
    let context = AppContext::load()?;
    let mut shell = context.chat_shell()?;
    let message_index = shell
        .append_outbound_message(
            conversation_id,
            sender_id_hex,
            message,
            current_chat_bootstrap_time_ms(),
        )
        .map_err(|error| error.to_string())?;
    shell
        .save(context.storage_secret())
        .map_err(|error| error.to_string())?;
    Ok(message_index)
}

pub fn receive_reviewed_chat_message(
    conversation_id: &str,
    sender_id_hex: Option<&str>,
    message: &str,
) -> Result<u64, String> {
    let context = AppContext::load()?;
    let mut shell = context.chat_shell()?;
    let contacts = context.contact_book()?.contacts();
    let sender_id_hex = match sender_id_hex
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(sender_id_hex) => sender_id_hex.to_owned(),
        None => shell
            .conversations()
            .into_iter()
            .find(|conversation| conversation.id_hex == conversation_id)
            .and_then(|conversation| conversation.member_fingerprints_hex.into_iter().next())
            .ok_or_else(|| {
                "reviewed inbound message requires a sender id or direct contact member".to_owned()
            })?,
    };
    enforce_incoming_policy(&context.config, &contacts, &sender_id_hex)?;
    let message_index = shell
        .append_inbound_review_message(
            conversation_id,
            &sender_id_hex,
            message,
            current_chat_bootstrap_time_ms(),
        )
        .map_err(|error| error.to_string())?;
    shell
        .save(context.storage_secret())
        .map_err(|error| error.to_string())?;
    Ok(message_index)
}

fn enforce_incoming_policy(
    config: &AppConfig,
    contacts: &[ContactRecord],
    sender_id_hex: &str,
) -> Result<(), String> {
    let sender_is_contact = contacts
        .iter()
        .any(|contact| contact.fingerprint_hex.eq_ignore_ascii_case(sender_id_hex));
    if config.chat.incoming_message_policy == IncomingMessagePolicy::ContactsOnly
        && !sender_is_contact
    {
        return Err("incoming messages from unknown senders are blocked by policy".to_owned());
    }
    match config.chat.default_chat_list_mode {
        ChatListMode::None => Ok(()),
        ChatListMode::Whitelist => {
            if access_list_matches(&config.chat.whitelist, contacts, sender_id_hex) {
                Ok(())
            } else {
                Err("incoming sender is not on the whitelist".to_owned())
            }
        }
        ChatListMode::Blacklist => {
            if access_list_matches(&config.chat.blacklist, contacts, sender_id_hex) {
                Err("incoming sender is on the blacklist".to_owned())
            } else {
                Ok(())
            }
        }
    }
}

fn access_list_matches(
    entries: &[String],
    contacts: &[ContactRecord],
    sender_id_hex: &str,
) -> bool {
    entries.iter().any(|entry| {
        entry.eq_ignore_ascii_case(sender_id_hex)
            || contacts.iter().any(|contact| {
                contact.alias.eq_ignore_ascii_case(entry)
                    && contact.fingerprint_hex.eq_ignore_ascii_case(sender_id_hex)
            })
    })
}
