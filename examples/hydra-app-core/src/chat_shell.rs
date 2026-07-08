use std::path::Path;

use crate::{
    contact_hex_decode, contact_hex_encode, current_chat_bootstrap_time_ms, AppError, AppResult,
    ConversationId, ConversationKind, MessageDirection, MessageStore, StoredMember, StoredMessage,
};

const MAX_CHAT_PLAINTEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatConversationSummary {
    pub id_hex: String,
    pub kind: ConversationKind,
    pub kind_label: &'static str,
    pub created_at_ms: u64,
    pub current_epoch: u64,
    pub current_state_version: u64,
    pub member_fingerprints_hex: Vec<String>,
    pub message_count: usize,
    pub last_message_preview: String,
    pub last_message_direction: Option<MessageDirection>,
    pub last_message_at_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatMessageSummary {
    pub conversation_id_hex: String,
    pub direction: MessageDirection,
    pub direction_label: &'static str,
    pub sender_id_hex: String,
    pub epoch: u64,
    pub state_version: u64,
    pub message_index: u64,
    pub received_at_ms: u64,
    pub content_preview: String,
}

pub struct ChatShell {
    store: MessageStore,
}

impl ChatShell {
    pub fn open_or_create(path: impl AsRef<Path>, password: &[u8]) -> AppResult<Self> {
        let path = path.as_ref();
        let store = if path.exists() {
            MessageStore::load(path, password)?
        } else {
            MessageStore::create(path, password)?
        };
        Ok(Self { store })
    }

    #[must_use]
    pub fn conversations(&self) -> Vec<ChatConversationSummary> {
        let mut summaries = self
            .store
            .conversations()
            .iter()
            .map(|conversation| {
                let messages = self
                    .store
                    .messages()
                    .iter()
                    .filter(|message| message.conversation_id == conversation.id);
                let mut message_count = 0_usize;
                let mut last_message = None;
                for message in messages {
                    message_count += 1;
                    if last_message.as_ref().is_none_or(|last: &&StoredMessage| {
                        message.received_at_ms >= last.received_at_ms
                    }) {
                        last_message = Some(message);
                    }
                }
                ChatConversationSummary {
                    id_hex: conversation_id_hex(conversation.id),
                    kind: conversation.kind,
                    kind_label: conversation_kind_label(conversation.kind),
                    created_at_ms: conversation.created_at_ms,
                    current_epoch: conversation.current_epoch,
                    current_state_version: conversation.current_state_version,
                    member_fingerprints_hex: conversation
                        .members
                        .iter()
                        .map(|member| contact_hex_encode(&member.identity_fingerprint.0))
                        .collect(),
                    message_count,
                    last_message_preview: last_message
                        .map(|message| content_preview(&message.content))
                        .unwrap_or_default(),
                    last_message_direction: last_message.map(|message| message.direction),
                    last_message_at_ms: last_message.map(|message| message.received_at_ms),
                }
            })
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| {
            right
                .last_message_at_ms
                .unwrap_or(right.created_at_ms)
                .cmp(&left.last_message_at_ms.unwrap_or(left.created_at_ms))
        });
        summaries
    }

    pub fn messages_for(&self, conversation_id_hex: &str) -> AppResult<Vec<ChatMessageSummary>> {
        let conversation_id = parse_conversation_id_hex(conversation_id_hex)?;
        let mut messages = self
            .store
            .messages_for(conversation_id)?
            .into_iter()
            .map(|message| ChatMessageSummary {
                conversation_id_hex: conversation_id_hex.to_owned(),
                direction: message.direction,
                direction_label: message_direction_label(message.direction),
                sender_id_hex: contact_hex_encode(&message.sender_id),
                epoch: message.epoch,
                state_version: message.state_version,
                message_index: message.message_index,
                received_at_ms: message.received_at_ms,
                content_preview: content_preview(&message.content),
            })
            .collect::<Vec<_>>();
        messages.sort_by_key(|message| (message.received_at_ms, message.message_index));
        Ok(messages)
    }

    pub fn create_direct_conversation(
        &mut self,
        peer_fingerprint_hex: &str,
        now_ms: u64,
    ) -> AppResult<ConversationId> {
        let peer_fingerprint = decode_32_hex(peer_fingerprint_hex, "peer fingerprint")?;
        if let Some(existing) = self.store.conversations().iter().find(|conversation| {
            conversation.kind == ConversationKind::Direct
                && conversation
                    .members
                    .iter()
                    .any(|member| member.identity_fingerprint.0 == peer_fingerprint)
        }) {
            return Ok(existing.id);
        }
        let conversation_id = self
            .store
            .create_conversation(ConversationKind::Direct, now_ms)?;
        self.store.upsert_member(
            conversation_id,
            StoredMember {
                member_id: peer_fingerprint,
                identity_fingerprint: hydra_core::types::IdentityFingerprint(peer_fingerprint),
                role: 0,
                active: true,
            },
        )?;
        Ok(conversation_id)
    }

    pub fn create_group_conversation(
        &mut self,
        kind: ConversationKind,
        now_ms: u64,
    ) -> AppResult<ConversationId> {
        match kind {
            ConversationKind::GroupLite
            | ConversationKind::GroupInteractive
            | ConversationKind::GroupBroadcast => self.store.create_conversation(kind, now_ms),
            ConversationKind::Direct => Err(AppError::InvalidInput(
                "direct conversations require a contact fingerprint",
            )),
        }
    }

    pub fn append_outbound_message(
        &mut self,
        conversation_id_hex: &str,
        sender_id_hex: &str,
        body: &str,
        now_ms: u64,
    ) -> AppResult<u64> {
        self.append_message(
            conversation_id_hex,
            sender_id_hex,
            body,
            now_ms,
            MessageDirection::Outbound,
        )
    }

    pub fn append_inbound_review_message(
        &mut self,
        conversation_id_hex: &str,
        sender_id_hex: &str,
        body: &str,
        now_ms: u64,
    ) -> AppResult<u64> {
        self.append_message(
            conversation_id_hex,
            sender_id_hex,
            body,
            now_ms,
            MessageDirection::Inbound,
        )
    }

    pub fn save(&self, password: &[u8]) -> AppResult<()> {
        self.store.save(password)
    }

    fn append_message(
        &mut self,
        conversation_id_hex: &str,
        sender_id_hex: &str,
        body: &str,
        now_ms: u64,
        direction: MessageDirection,
    ) -> AppResult<u64> {
        let trimmed = body.trim();
        if trimmed.is_empty() {
            return Err(AppError::InvalidInput("chat message body is required"));
        }
        if trimmed.len() > MAX_CHAT_PLAINTEXT_BYTES {
            return Err(AppError::InvalidInput("chat message body is too large"));
        }
        let conversation_id = parse_conversation_id_hex(conversation_id_hex)?;
        let sender_id = decode_32_hex(sender_id_hex, "sender id")?;
        let message_index = self
            .store
            .messages_for(conversation_id)?
            .into_iter()
            .filter(|message| message.sender_id == sender_id)
            .map(|message| message.message_index)
            .max()
            .map_or(0, |index| index.saturating_add(1));
        self.store.append_message(StoredMessage {
            conversation_id,
            direction,
            sender_id,
            epoch: 0,
            state_version: 0,
            message_index,
            received_at_ms: now_ms,
            content: trimmed.as_bytes().to_vec(),
        })?;
        Ok(message_index)
    }
}

#[must_use]
pub fn conversation_id_hex(id: ConversationId) -> String {
    contact_hex_encode(&id.0)
}

pub fn parse_conversation_id_hex(hex: &str) -> AppResult<ConversationId> {
    Ok(ConversationId(decode_32_hex(hex, "conversation id")?))
}

#[must_use]
pub const fn conversation_kind_label(kind: ConversationKind) -> &'static str {
    match kind {
        ConversationKind::Direct => "direct",
        ConversationKind::GroupLite => "group-lite",
        ConversationKind::GroupInteractive => "group-interactive",
        ConversationKind::GroupBroadcast => "group-broadcast",
    }
}

pub fn conversation_kind_from_label(label: &str) -> AppResult<ConversationKind> {
    match label.trim() {
        "group-lite" | "lite" => Ok(ConversationKind::GroupLite),
        "group-interactive" | "interactive" => Ok(ConversationKind::GroupInteractive),
        "group-broadcast" | "broadcast" => Ok(ConversationKind::GroupBroadcast),
        _ => Err(AppError::InvalidInput("unsupported group chat kind")),
    }
}

#[must_use]
pub const fn message_direction_label(direction: MessageDirection) -> &'static str {
    match direction {
        MessageDirection::Outbound => "outbound",
        MessageDirection::Inbound => "inbound",
    }
}

#[must_use]
pub fn now_ms() -> u64 {
    current_chat_bootstrap_time_ms()
}

fn decode_32_hex(hex: &str, field: &'static str) -> AppResult<[u8; 32]> {
    let bytes = contact_hex_decode(hex)?;
    if bytes.len() != 32 {
        return Err(AppError::InvalidInput(match field {
            "conversation id" => "conversation id must be 32 bytes",
            "sender id" => "sender id must be 32 bytes",
            "peer fingerprint" => "peer fingerprint must be 32 bytes",
            _ => "hex field must be 32 bytes",
        }));
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn content_preview(content: &[u8]) -> String {
    let text = String::from_utf8_lossy(content);
    let mut preview = text.chars().take(240).collect::<String>();
    if text.chars().count() > 240 {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn chat_shell_creates_direct_and_stores_messages() {
        let path = std::env::temp_dir().join(format!(
            "hydra-chat-shell-{}.db",
            current_chat_bootstrap_time_ms()
        ));
        let password = [7_u8; 32];
        let peer = [0x42_u8; 32];
        let sender = [0x24_u8; 32];
        let mut shell = ChatShell::open_or_create(&path, &password).unwrap();
        let conversation = shell
            .create_direct_conversation(&contact_hex_encode(&peer), 100)
            .unwrap();
        let index = shell
            .append_outbound_message(
                &conversation_id_hex(conversation),
                &contact_hex_encode(&sender),
                "hello",
                200,
            )
            .unwrap();
        assert_eq!(index, 0);
        shell.save(&password).unwrap();

        let shell = ChatShell::open_or_create(&path, &password).unwrap();
        let conversations = shell.conversations();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].message_count, 1);
        let messages = shell.messages_for(&conversations[0].id_hex).unwrap();
        assert_eq!(messages[0].content_preview, "hello");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn chat_shell_rejects_wrong_conversation_id_boundary() {
        let path = std::env::temp_dir().join(format!(
            "hydra-chat-shell-bad-{}.db",
            current_chat_bootstrap_time_ms()
        ));
        let password = [9_u8; 32];
        let mut shell = ChatShell::open_or_create(&path, &password).unwrap();
        let error = shell
            .append_outbound_message("abcd", &contact_hex_encode(&[0x11_u8; 32]), "hello", 1)
            .unwrap_err();
        assert_eq!(
            error,
            AppError::InvalidInput("conversation id must be 32 bytes")
        );
        let _ = fs::remove_file(path);
    }
}
