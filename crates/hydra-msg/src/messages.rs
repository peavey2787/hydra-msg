use crate::{
    codec::*, ContactId, Hydra, HydraEnvelope, HydraMsgError, HydraResult, LobbyId,
    MESSAGES_MAGIC,
};
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::fs;

/// HYDRA local message id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub(crate) u64);

impl MessageId {
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Message attachment origin retained for receive-side convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HydraAttachmentSource {
    File,
    Bytes,
}

/// Public attachment helper. Internally this is just payload packaging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraAttachment {
    pub(crate) filename: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) source: HydraAttachmentSource,
}

impl HydraAttachment {
    pub fn from_file(path: impl AsRef<Path>) -> HydraResult<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = path;
            return Err(HydraMsgError::Unsupported(
                "from_file is not available in browser WASM; use attach_bytes/from_named_bytes",
            ));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = path.as_ref();
            let bytes = fs::read(path)?;
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(HydraMsgError::InvalidInput(
                    "attachment path has no valid filename",
                ))?
                .to_string();
            Ok(Self {
                filename,
                bytes,
                source: HydraAttachmentSource::File,
            })
        }
    }

    /// Creates an in-memory attachment with a safe default filename.
    ///
    /// This exists so app developers can do `HydraAttachment::from_bytes(bytes)`
    /// without caring about internal payload packaging. Use
    /// [`HydraAttachment::from_named_bytes`] or
    /// [`HydraMessage::attach_bytes`] when the app wants a specific filename.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> HydraResult<Self> {
        Self::from_named_bytes("attachment.bin", bytes)
    }

    pub fn from_named_bytes(
        filename: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> HydraResult<Self> {
        let filename = filename.into();
        if filename.is_empty() {
            return Err(HydraMsgError::InvalidInput("attachment filename is empty"));
        }
        Ok(Self {
            filename,
            bytes: bytes.into(),
            source: HydraAttachmentSource::Bytes,
        })
    }

    pub fn with_filename(mut self, filename: impl Into<String>) -> HydraResult<Self> {
        let filename = filename.into();
        if filename.is_empty() {
            return Err(HydraMsgError::InvalidInput("attachment filename is empty"));
        }
        self.filename = filename;
        Ok(self)
    }

    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn source(&self) -> HydraAttachmentSource {
        self.source
    }

    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self.source, HydraAttachmentSource::File)
    }

    #[must_use]
    pub const fn is_bytes(&self) -> bool {
        matches!(self.source, HydraAttachmentSource::Bytes)
    }
}

/// Public outbound message builder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HydraMessage {
    pub plaintext: Vec<u8>,
    pub attachments: Vec<HydraAttachment>,
}

impl HydraMessage {
    #[must_use]
    pub fn text(text: impl AsRef<str>) -> Self {
        Self {
            plaintext: text.as_ref().as_bytes().to_vec(),
            attachments: Vec::new(),
        }
    }

    #[must_use]
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            plaintext: bytes.into(),
            attachments: Vec::new(),
        }
    }

    pub fn attach_file(mut self, path: impl AsRef<Path>) -> HydraResult<Self> {
        self.attachments.push(HydraAttachment::from_file(path)?);
        Ok(self)
    }

    pub fn attach_bytes(
        mut self,
        filename: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> HydraResult<Self> {
        self.attachments
            .push(HydraAttachment::from_named_bytes(filename, bytes)?);
        Ok(self)
    }

    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    #[must_use]
    pub fn attachments(&self) -> &[HydraAttachment] {
        &self.attachments
    }
}

impl From<&[u8]> for HydraMessage {
    fn from(value: &[u8]) -> Self {
        Self::bytes(value.to_vec())
    }
}

impl From<Vec<u8>> for HydraMessage {
    fn from(value: Vec<u8>) -> Self {
        Self::bytes(value)
    }
}

impl<const N: usize> From<&[u8; N]> for HydraMessage {
    fn from(value: &[u8; N]) -> Self {
        Self::bytes(value.to_vec())
    }
}

impl From<&str> for HydraMessage {
    fn from(value: &str) -> Self {
        Self::text(value)
    }
}

impl From<String> for HydraMessage {
    fn from(value: String) -> Self {
        Self::text(value)
    }
}

/// Public decrypted receive result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedHydraMessage {
    pub(crate) from: ContactId,
    pub(crate) message_id: MessageId,
    pub(crate) lobby_id: Option<LobbyId>,
    pub(crate) plaintext: Vec<u8>,
    pub(crate) attachments: Vec<HydraAttachment>,
}

impl ReceivedHydraMessage {
    #[must_use]
    pub const fn from(&self) -> ContactId {
        self.from
    }

    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    #[must_use]
    pub const fn lobby_id(&self) -> Option<LobbyId> {
        self.lobby_id
    }

    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub fn text(&self) -> HydraResult<String> {
        String::from_utf8(self.plaintext.clone())
            .map_err(|_| HydraMsgError::InvalidEncoding("message plaintext is not utf-8"))
    }

    #[must_use]
    pub fn attachments(&self) -> &[HydraAttachment] {
        &self.attachments
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoredMessage {
    pub(crate) id: MessageId,
    pub(crate) contact_id: ContactId,
    pub(crate) inbound: bool,
    pub(crate) plaintext: Vec<u8>,
    pub(crate) attachments: Vec<HydraAttachment>,
}

impl Hydra {
    pub fn send(
        &mut self,
        contact_id: ContactId,
        message: impl Into<HydraMessage>,
    ) -> HydraResult<HydraEnvelope> {
        let message = message.into();
        let payload = pack_message(&message)?;
        let envelope = self.seal_payload_for_contact(contact_id, &payload)?;
        self.store_message(contact_id, false, message.plaintext, message.attachments);
        self.persist()?;
        Ok(envelope)
    }

    pub fn receive(&mut self, envelope: impl AsRef<[u8]>) -> HydraResult<ReceivedHydraMessage> {
        let (from, payload) = self.open_payload_from_contact(envelope.as_ref())?;
        let message = unpack_message(&payload, from, MessageId(self.next_message_id), None)?;
        self.store_message(
            from,
            true,
            message.plaintext.clone(),
            message.attachments.clone(),
        );
        self.persist()?;
        Ok(message)
    }

    #[must_use]
    pub fn list_messages(&self, contact_id: ContactId) -> Vec<MessageId> {
        self.messages
            .iter()
            .filter(|message| message.contact_id == contact_id)
            .map(|message| message.id)
            .collect()
    }

    pub fn get_message(&self, message_id: MessageId) -> HydraResult<ReceivedHydraMessage> {
        let stored = self
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .ok_or(HydraMsgError::MessageNotFound)?;
        Ok(ReceivedHydraMessage {
            from: stored.contact_id,
            message_id: stored.id,
            lobby_id: None,
            plaintext: stored.plaintext.clone(),
            attachments: stored.attachments.clone(),
        })
    }

    pub fn delete_message(&mut self, message_id: MessageId) -> HydraResult<()> {
        let before = self.messages.len();
        self.messages.retain(|message| message.id != message_id);
        if self.messages.len() == before {
            return Err(HydraMsgError::MessageNotFound);
        }
        self.persist()?;
        Ok(())
    }

    pub fn clear_messages(&mut self, contact_id: ContactId) -> HydraResult<()> {
        self.messages
            .retain(|message| message.contact_id != contact_id);
        self.persist()?;
        Ok(())
    }

    pub fn export_messages(&self) -> HydraResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(MESSAGES_MAGIC);
        for message in &self.messages {
            out.extend_from_slice(encode_message_line(message).as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }

    pub fn import_messages(&mut self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        let text = std::str::from_utf8(bytes.as_ref())
            .map_err(|_| HydraMsgError::InvalidEncoding("messages export is not utf-8"))?;
        if !text.starts_with(std::str::from_utf8(MESSAGES_MAGIC).unwrap_or_default()) {
            return Err(HydraMsgError::InvalidEncoding("messages export magic"));
        }
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let message = decode_message_line(line)?;
            self.next_message_id = self.next_message_id.max(message.id.0.saturating_add(1));
            self.messages.push(message);
        }
        self.persist()?;
        Ok(())
    }

    pub(crate) fn store_message(
        &mut self,
        contact_id: ContactId,
        inbound: bool,
        plaintext: Vec<u8>,
        attachments: Vec<HydraAttachment>,
    ) -> MessageId {
        let id = MessageId(self.next_message_id);
        self.next_message_id = self.next_message_id.saturating_add(1);
        self.messages.push(StoredMessage {
            id,
            contact_id,
            inbound,
            plaintext,
            attachments,
        });
        id
    }
}
