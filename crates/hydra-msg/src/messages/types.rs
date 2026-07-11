use crate::{
    limits::{
        reject_input_size, MAX_ATTACHMENTS_PER_MESSAGE, MAX_ATTACHMENT_BYTES,
        MAX_ATTACHMENT_FILENAME_BYTES,
    },
    ContactId, HydraMsgError, HydraResult, LobbyId,
};
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::{fs::File, io::Read};

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
            let file = File::open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(HydraMsgError::InvalidInput(
                    "attachment path is not a regular file",
                ));
            }
            let file_len = usize::try_from(metadata.len())
                .map_err(|_| HydraMsgError::InvalidInput("attachment size"))?;
            reject_input_size(file_len, MAX_ATTACHMENT_BYTES, "attachment size")?;
            let read_limit = u64::try_from(MAX_ATTACHMENT_BYTES)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(HydraMsgError::InvalidInput("attachment size"))?;
            let mut bytes = Vec::with_capacity(file_len.min(64 * 1024));
            file.take(read_limit).read_to_end(&mut bytes)?;
            reject_input_size(bytes.len(), MAX_ATTACHMENT_BYTES, "attachment size")?;
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(HydraMsgError::InvalidInput(
                    "attachment path has no valid filename",
                ))?
                .to_string();
            validate_attachment_filename_input(&filename)?;
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
        validate_attachment_filename_input(&filename)?;
        let bytes = bytes.into();
        reject_input_size(bytes.len(), MAX_ATTACHMENT_BYTES, "attachment size")?;
        Ok(Self {
            filename,
            bytes,
            source: HydraAttachmentSource::Bytes,
        })
    }

    pub fn with_filename(mut self, filename: impl Into<String>) -> HydraResult<Self> {
        let filename = filename.into();
        validate_attachment_filename_input(&filename)?;
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
        if self.attachments.len() >= MAX_ATTACHMENTS_PER_MESSAGE {
            return Err(HydraMsgError::InvalidInput("attachment count"));
        }
        self.attachments.push(HydraAttachment::from_file(path)?);
        Ok(self)
    }

    pub fn attach_bytes(
        mut self,
        filename: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> HydraResult<Self> {
        if self.attachments.len() >= MAX_ATTACHMENTS_PER_MESSAGE {
            return Err(HydraMsgError::InvalidInput("attachment count"));
        }
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MessageUsage {
    pub(crate) count: usize,
    pub(crate) bytes: usize,
}

fn validate_attachment_filename_input(filename: &str) -> HydraResult<()> {
    if filename.is_empty() {
        return Err(HydraMsgError::InvalidInput("attachment filename is empty"));
    }
    reject_input_size(
        filename.len(),
        MAX_ATTACHMENT_FILENAME_BYTES,
        "attachment filename size",
    )
}
