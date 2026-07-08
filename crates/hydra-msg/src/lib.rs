//! Stupid-simple public HYDRA-MSG facade.
//!
//! This crate is the app developer entry point. It intentionally hides crypto,
//! envelope, ratchet, chunking, and wire-format internals behind a small API.
//! Carriers such as WebRTC, files, HTTP, QR codes, relays, libp2p, Kaspa
//! pointers, and mailboxes only move the opaque bytes returned by this crate.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(not(target_arch = "wasm32"))]
use std::fs;

use hydra_core::{FULL_MAX_CONTENT_SIZE, HASH_SIZE, ML_DSA_65_VK_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};
use hydra_session::{derive_initial_secrets, SessionError, SessionRole, SessionState};

mod codec;
use codec::*;

const CONTACT_CARD_MAGIC: &str = "HYDRA-MSG-CONTACT-V1";
const ID_EXPORT_MAGIC: &[u8] = b"HYDRA-MSG-ID-V1\n";
const OFFER_MAGIC: &[u8] = b"HYDRA-MSG-OFFER-V1\n";
const ANSWER_MAGIC: &[u8] = b"HYDRA-MSG-ANSWER-V1\n";
const PAYLOAD_MAGIC: &[u8] = b"HYDRA-MSG-PAYLOAD-V1\n";
const LOBBY_INVITE_MAGIC: &str = "HYDRA-MSG-LOBBY-INVITE-V1";
const LOBBY_PAYLOAD_MAGIC: &[u8] = b"HYDRA-MSG-LOBBY-PAYLOAD-V1\n";
const BACKUP_MAGIC: &[u8] = b"HYDRA-MSG-BACKUP-V1\n";
const STATE_MAGIC: &[u8] = b"HYDRA-MSG-STATE-V1\n";
const CONTACTS_MAGIC: &[u8] = b"HYDRA-MSG-CONTACTS-V1\n";
const MESSAGES_MAGIC: &[u8] = b"HYDRA-MSG-MESSAGES-V1\n";
#[cfg(not(target_arch = "wasm32"))]
const STATE_FILE_NAME: &str = "state-v1.hydra";

/// Public facade result type.
pub type HydraResult<T> = Result<T, HydraMsgError>;

/// Public facade error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydraMsgError {
    Io(String),
    EntropyUnavailable,
    InvalidInput(&'static str),
    InvalidEncoding(&'static str),
    InvalidPassword,
    IdentityNotFound,
    ContactNotFound,
    SessionNotFound,
    LobbyNotFound,
    MessageNotFound,
    PayloadTooLarge,
    Unsupported(&'static str),
    Crypto(String),
    Session(String),
}

impl fmt::Display for HydraMsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for HydraMsgError {}

impl From<std::io::Error> for HydraMsgError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<hydra_crypto::CryptoError> for HydraMsgError {
    fn from(value: hydra_crypto::CryptoError) -> Self {
        Self::Crypto(value.to_string())
    }
}

impl From<SessionError> for HydraMsgError {
    fn from(value: SessionError) -> Self {
        Self::Session(value.to_string())
    }
}

/// HYDRA identity id/fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdentityId([u8; HASH_SIZE]);

/// HYDRA contact id. In v1 this is the contact identity fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContactId([u8; HASH_SIZE]);

/// HYDRA local message id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(u64);

/// HYDRA lobby id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LobbyId([u8; HASH_SIZE]);

impl IdentityId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: impl AsRef<str>) -> HydraResult<Self> {
        Ok(Self(exact_array_from_vec(hex_decode(hex.as_ref())?)?))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    #[must_use]
    pub fn hex(self) -> String {
        hex_encode(&self.0)
    }
}

impl ContactId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: impl AsRef<str>) -> HydraResult<Self> {
        Ok(Self(exact_array_from_vec(hex_decode(hex.as_ref())?)?))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    #[must_use]
    pub fn hex(self) -> String {
        hex_encode(&self.0)
    }
}

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

impl LobbyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: impl AsRef<str>) -> HydraResult<Self> {
        Ok(Self(exact_array_from_vec(hex_decode(hex.as_ref())?)?))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    #[must_use]
    pub fn hex(self) -> String {
        hex_encode(&self.0)
    }
}

/// Opaque handshake offer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeOffer(Vec<u8>);

/// Opaque handshake answer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeAnswer(Vec<u8>);

/// Opaque encrypted HYDRA envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraEnvelope(Vec<u8>);

/// Recipient-tagged lobby envelope returned by `send_lobby`.
///
/// The envelope bytes are still opaque HYDRA bytes. The recipient id is only a
/// routing hint so app developers know which lobby member should receive each
/// per-member encrypted copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobbyEnvelope {
    recipient: ContactId,
    envelope: HydraEnvelope,
}

impl HandshakeOffer {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HandshakeOffer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HandshakeAnswer {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HandshakeAnswer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HydraEnvelope {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HydraEnvelope {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HydraLobbyEnvelope {
    #[must_use]
    pub const fn recipient(&self) -> ContactId {
        self.recipient
    }

    #[must_use]
    pub const fn envelope(&self) -> &HydraEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn into_envelope(self) -> HydraEnvelope {
        self.envelope
    }

    #[must_use]
    pub fn into_parts(self) -> (ContactId, HydraEnvelope) {
        (self.recipient, self.envelope)
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
    filename: String,
    bytes: Vec<u8>,
    source: HydraAttachmentSource,
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
    from: ContactId,
    message_id: MessageId,
    lobby_id: Option<LobbyId>,
    plaintext: Vec<u8>,
    attachments: Vec<HydraAttachment>,
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

/// Public contact metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraContact {
    id: ContactId,
    label: String,
    public_key: [u8; ML_DSA_65_VK_SIZE],
    verified: bool,
    blocked: bool,
}

impl HydraContact {
    #[must_use]
    pub const fn id(&self) -> ContactId {
        self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; ML_DSA_65_VK_SIZE] {
        &self.public_key
    }

    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    #[must_use]
    pub const fn blocked(&self) -> bool {
        self.blocked
    }

    #[must_use]
    pub fn safety_code(&self) -> String {
        safety_code_for_contact(self.id)
    }
}

/// Public identity metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraIdentitySummary {
    id: IdentityId,
    label: String,
    unlocked: bool,
}

impl HydraIdentitySummary {
    #[must_use]
    pub const fn id(&self) -> IdentityId {
        self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub const fn unlocked(&self) -> bool {
        self.unlocked
    }
}

/// Session status exposed to normal developers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HydraSessionStatus {
    Missing,
    Active,
    Closed,
}

/// Lobby creation policy placeholder for the simple public API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobbyPolicy {
    pub max_members: usize,
    pub label: String,
}

impl HydraLobbyPolicy {
    #[must_use]
    pub fn new(label: impl Into<String>, max_members: usize) -> Self {
        Self {
            label: label.into(),
            max_members,
        }
    }
}

impl Default for HydraLobbyPolicy {
    fn default() -> Self {
        Self::new("HYDRA lobby", 64)
    }
}

/// Lobby summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobby {
    id: LobbyId,
    policy: HydraLobbyPolicy,
    members: Vec<ContactId>,
}

impl HydraLobby {
    #[must_use]
    pub const fn id(&self) -> LobbyId {
        self.id
    }

    #[must_use]
    pub const fn policy(&self) -> &HydraLobbyPolicy {
        &self.policy
    }

    #[must_use]
    pub fn members(&self) -> &[ContactId] {
        &self.members
    }
}

/// Opaque lobby invite bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobbyInvite(Vec<u8>);

impl HydraLobbyInvite {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HydraLobbyInvite {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Local storage summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraStorageStatus {
    pub data_dir: PathBuf,
    pub identity_count: usize,
    pub contact_count: usize,
    pub session_count: usize,
    pub message_count: usize,
    pub lobby_count: usize,
}

/// Simple benchmark report.
#[derive(Clone, Debug, PartialEq)]
pub struct HydraBenchmarkReport {
    pub suite: &'static str,
    pub iterations: u32,
    pub handshake_avg_ms: f64,
    pub send_receive_avg_ms: f64,
}

#[derive(Clone)]
struct IdentityRecord {
    id: IdentityId,
    label: String,
    seed: Option<[u8; 32]>,
    public_key: [u8; ML_DSA_65_VK_SIZE],
    password_tag: [u8; 32],
    seed_nonce: [u8; 12],
    encrypted_seed: Vec<u8>,
    unlocked: bool,
}

struct SessionRecord {
    state: SessionState,
    closed: bool,
}

#[derive(Clone)]
struct PendingOffer {
    contact_id: ContactId,
    nonce: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredMessage {
    id: MessageId,
    contact_id: ContactId,
    inbound: bool,
    plaintext: Vec<u8>,
    attachments: Vec<HydraAttachment>,
}

/// Main public HYDRA facade.
pub struct Hydra {
    data_dir: PathBuf,
    identities: HashMap<IdentityId, IdentityRecord>,
    active_id: Option<IdentityId>,
    contacts: HashMap<ContactId, HydraContact>,
    pending_offers: HashMap<[u8; 32], PendingOffer>,
    sessions: HashMap<ContactId, SessionRecord>,
    messages: Vec<StoredMessage>,
    next_message_id: u64,
    lobbies: HashMap<LobbyId, HydraLobby>,
}

impl Hydra {
    pub fn open(data_dir: impl AsRef<Path>) -> HydraResult<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        #[cfg(not(target_arch = "wasm32"))]
        fs::create_dir_all(&data_dir)?;
        let mut hydra = Self {
            data_dir,
            identities: HashMap::new(),
            active_id: None,
            contacts: HashMap::new(),
            pending_offers: HashMap::new(),
            sessions: HashMap::new(),
            messages: Vec::new(),
            next_message_id: 1,
            lobbies: HashMap::new(),
        };
        hydra.load_state()?;
        Ok(hydra)
    }

    pub fn open_default() -> HydraResult<Self> {
        Self::open("hydra-msg-data")
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn generate_id(&mut self, password: impl AsRef<str>) -> HydraResult<IdentityId> {
        let seed = random_array::<32>()?;
        let record = identity_record_from_seed(
            format!("identity-{}", self.identities.len() + 1),
            seed,
            password.as_ref(),
            true,
        )?;
        let id = record.id;
        self.identities.insert(id, record);
        self.persist()?;
        Ok(id)
    }

    pub fn import_id(
        &mut self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<IdentityId> {
        let seed = decode_identity_export(bytes.as_ref())?;
        let record = identity_record_from_seed(
            format!("imported-{}", self.identities.len() + 1),
            seed,
            password.as_ref(),
            false,
        )?;
        let id = record.id;
        self.identities.insert(id, record);
        self.persist()?;
        Ok(id)
    }

    pub fn export_id(&self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        let record = self
            .identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        verify_password(record, password.as_ref())?;
        Ok(encode_identity_export(
            &self.identity_seed(record, password.as_ref())?,
        ))
    }

    #[must_use]
    pub fn list_ids(&self) -> Vec<HydraIdentitySummary> {
        self.identities
            .values()
            .map(|record| HydraIdentitySummary {
                id: record.id,
                label: record.label.clone(),
                unlocked: record.unlocked,
            })
            .collect()
    }

    pub fn get_id(&self, id: IdentityId) -> HydraResult<HydraIdentitySummary> {
        let record = self
            .identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        Ok(HydraIdentitySummary {
            id: record.id,
            label: record.label.clone(),
            unlocked: record.unlocked,
        })
    }

    #[must_use]
    pub const fn active_id(&self) -> Option<IdentityId> {
        self.active_id
    }

    pub fn set_active_id(&mut self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<()> {
        self.unlock_id(id, password)?;
        self.active_id = Some(id);
        Ok(())
    }

    pub fn unlock_id(&mut self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<()> {
        let record = self
            .identities
            .get_mut(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        verify_password(record, password.as_ref())?;
        record.seed = Some(decrypt_seed(record, password.as_ref())?);
        record.unlocked = true;
        Ok(())
    }

    pub fn lock_id(&mut self, id: IdentityId) -> HydraResult<()> {
        let record = self
            .identities
            .get_mut(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        record.seed = None;
        record.unlocked = false;
        if self.active_id == Some(id) {
            self.active_id = None;
        }
        Ok(())
    }

    pub fn lock_active_id(&mut self) -> HydraResult<()> {
        let id = self.active_id.ok_or(HydraMsgError::IdentityNotFound)?;
        self.lock_id(id)
    }

    pub fn rename_id(&mut self, id: IdentityId, label: impl Into<String>) -> HydraResult<()> {
        let record = self
            .identities
            .get_mut(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        record.label = label.into();
        self.persist()?;
        Ok(())
    }

    pub fn delete_id(&mut self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<()> {
        let record = self
            .identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        verify_password(record, password.as_ref())?;
        self.identities.remove(&id);
        if self.active_id == Some(id) {
            self.active_id = None;
        }
        self.persist()?;
        Ok(())
    }

    pub fn create_contact_card(&self) -> HydraResult<Vec<u8>> {
        let record = self.active_record()?;
        Ok(encode_contact_card(&record.label, &record.public_key))
    }

    pub fn create_contact_invite(&self) -> HydraResult<Vec<u8>> {
        self.create_contact_card()
    }

    pub fn add_contact(&mut self, contact_card: impl AsRef<[u8]>) -> HydraResult<HydraContact> {
        let contact = decode_contact_card(contact_card.as_ref())?;
        self.contacts.insert(contact.id, contact.clone());
        self.persist()?;
        Ok(contact)
    }

    pub fn import_contacts(&mut self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        let text = std::str::from_utf8(bytes.as_ref())
            .map_err(|_| HydraMsgError::InvalidEncoding("contacts export is not utf-8"))?;
        if text.starts_with(std::str::from_utf8(CONTACTS_MAGIC).unwrap_or_default()) {
            for line in text.lines().skip(1) {
                if line.trim().is_empty() {
                    continue;
                }
                let contact = decode_contact_line(line)?;
                self.contacts.insert(contact.id, contact);
            }
        } else {
            for block in text.split("\n---\n") {
                if block.trim().is_empty() {
                    continue;
                }
                self.add_contact(block.as_bytes())?;
            }
        }
        self.persist()?;
        Ok(())
    }

    pub fn export_contacts(&self) -> HydraResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(CONTACTS_MAGIC);
        for contact in self.contacts.values() {
            out.extend_from_slice(encode_contact_line(contact).as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }

    #[must_use]
    pub fn list_contacts(&self) -> Vec<HydraContact> {
        self.contacts.values().cloned().collect()
    }

    pub fn get_contact(&self, contact_id: ContactId) -> HydraResult<HydraContact> {
        self.contacts
            .get(&contact_id)
            .cloned()
            .ok_or(HydraMsgError::ContactNotFound)
    }

    pub fn verify_contact(
        &mut self,
        contact_id: ContactId,
        safety_code: impl AsRef<str>,
    ) -> HydraResult<()> {
        let expected = safety_code_for_contact(contact_id);
        if expected != safety_code.as_ref() {
            return Err(HydraMsgError::InvalidInput("contact safety code mismatch"));
        }
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.verified = true;
        self.persist()?;
        Ok(())
    }

    pub fn unverify_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.verified = false;
        self.persist()?;
        Ok(())
    }

    pub fn rename_contact(
        &mut self,
        contact_id: ContactId,
        label: impl Into<String>,
    ) -> HydraResult<()> {
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.label = label.into();
        self.persist()?;
        Ok(())
    }

    pub fn remove_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        self.contacts
            .remove(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        self.sessions.remove(&contact_id);
        self.persist()?;
        Ok(())
    }

    pub fn block_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.blocked = true;
        self.persist()?;
        Ok(())
    }

    pub fn unblock_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.blocked = false;
        self.persist()?;
        Ok(())
    }

    pub fn init_handshake(&mut self, contact_id: ContactId) -> HydraResult<HandshakeOffer> {
        self.require_contact(contact_id)?;
        let record = self.active_unlocked_record()?;
        let nonce = random_array::<32>()?;
        let offer = encode_handshake_offer(record.id, &record.public_key, nonce);
        self.pending_offers
            .insert(nonce, PendingOffer { contact_id, nonce });
        Ok(HandshakeOffer(offer))
    }

    pub fn reply_handshake(&mut self, offer: impl AsRef<[u8]>) -> HydraResult<HandshakeAnswer> {
        let parsed = decode_handshake_offer(offer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        let contact_id = ContactId(parsed.peer_id.0);
        self.contacts
            .entry(contact_id)
            .or_insert_with(|| HydraContact {
                id: contact_id,
                label: format!("contact-{}", contact_id.hex()),
                public_key: parsed.public_key,
                verified: false,
                blocked: false,
            });
        let (secret, transcript_hash) =
            derive_facade_handshake_material(parsed.nonce, parsed.peer_id, active.id);
        let secrets = derive_initial_secrets(&secret, &transcript_hash)?;
        let state = SessionState::established(
            SessionRole::Responder,
            transcript_hash,
            active.id.0,
            parsed.peer_id.0,
            secrets,
        );
        self.sessions.insert(
            contact_id,
            SessionRecord {
                state,
                closed: false,
            },
        );
        self.persist()?;
        Ok(HandshakeAnswer(encode_handshake_answer(
            active.id,
            &active.public_key,
            parsed.nonce,
        )))
    }

    pub fn finish_handshake(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<()> {
        let parsed = decode_handshake_answer(answer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        let pending = self
            .pending_offers
            .remove(&parsed.nonce)
            .ok_or(HydraMsgError::InvalidInput("unknown handshake answer"))?;
        if pending.contact_id != ContactId(parsed.peer_id.0) {
            return Err(HydraMsgError::InvalidInput(
                "handshake answer does not match pending contact",
            ));
        }
        let _ = pending.nonce;
        let (secret, transcript_hash) =
            derive_facade_handshake_material(parsed.nonce, active.id, parsed.peer_id);
        let secrets = derive_initial_secrets(&secret, &transcript_hash)?;
        let state = SessionState::established(
            SessionRole::Initiator,
            transcript_hash,
            active.id.0,
            parsed.peer_id.0,
            secrets,
        );
        self.sessions.insert(
            pending.contact_id,
            SessionRecord {
                state,
                closed: false,
            },
        );
        Ok(())
    }

    pub fn session_status(&self, contact_id: ContactId) -> HydraResult<HydraSessionStatus> {
        Ok(match self.sessions.get(&contact_id) {
            Some(session) if session.closed => HydraSessionStatus::Closed,
            Some(_) => HydraSessionStatus::Active,
            None => HydraSessionStatus::Missing,
        })
    }

    pub fn rekey_session(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        let refresh_id = random_array::<32>()?;
        session.state.begin_refresh(refresh_id)?;
        Ok(())
    }

    pub fn close_session(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        session.closed = true;
        Ok(())
    }

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

    pub fn create_lobby(&mut self, policy: HydraLobbyPolicy) -> HydraResult<HydraLobby> {
        validate_lobby_policy(&policy)?;
        let mut seed = Vec::new();
        seed.extend_from_slice(policy.label.as_bytes());
        seed.extend_from_slice(&random_array::<32>()?);
        let id = LobbyId(RustCryptoBackend::sha3_256(&seed));
        let lobby = HydraLobby {
            id,
            policy,
            members: Vec::new(),
        };
        self.lobbies.insert(id, lobby.clone());
        self.persist()?;
        Ok(lobby)
    }

    pub fn create_lobby_invite(&self, lobby_id: LobbyId) -> HydraResult<HydraLobbyInvite> {
        let lobby = self
            .lobbies
            .get(&lobby_id)
            .ok_or(HydraMsgError::LobbyNotFound)?;
        let members = self.lobby_invite_members(lobby);
        Ok(HydraLobbyInvite(encode_lobby_invite(lobby, &members)))
    }

    pub fn join_lobby(&mut self, invite: impl AsRef<[u8]>) -> HydraResult<HydraLobby> {
        let mut lobby = decode_lobby_invite(invite.as_ref())?;
        validate_lobby_policy(&lobby.policy)?;
        self.normalize_lobby_members_for_local_identity(&mut lobby);
        self.lobbies.insert(lobby.id, lobby.clone());
        self.persist()?;
        Ok(lobby)
    }

    pub fn leave_lobby(&mut self, lobby_id: LobbyId) -> HydraResult<()> {
        self.lobbies
            .remove(&lobby_id)
            .ok_or(HydraMsgError::LobbyNotFound)?;
        self.persist()?;
        Ok(())
    }

    #[must_use]
    pub fn list_lobbies(&self) -> Vec<HydraLobby> {
        self.lobbies.values().cloned().collect()
    }

    pub fn get_lobby(&self, lobby_id: LobbyId) -> HydraResult<HydraLobby> {
        self.lobbies
            .get(&lobby_id)
            .cloned()
            .ok_or(HydraMsgError::LobbyNotFound)
    }

    pub fn lobby_members(&self, lobby_id: LobbyId) -> HydraResult<Vec<ContactId>> {
        Ok(self.get_lobby(lobby_id)?.members)
    }

    pub fn add_lobby_member(
        &mut self,
        lobby_id: LobbyId,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        self.require_contact(contact_id)?;
        let mut changed = false;
        {
            let lobby = self
                .lobbies
                .get_mut(&lobby_id)
                .ok_or(HydraMsgError::LobbyNotFound)?;
            if !lobby.members.contains(&contact_id) {
                if lobby.members.len() >= lobby.policy.max_members {
                    return Err(HydraMsgError::InvalidInput("lobby member limit reached"));
                }
                lobby.members.push(contact_id);
                changed = true;
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    pub fn remove_lobby_member(
        &mut self,
        lobby_id: LobbyId,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        {
            let lobby = self
                .lobbies
                .get_mut(&lobby_id)
                .ok_or(HydraMsgError::LobbyNotFound)?;
            lobby.members.retain(|member| *member != contact_id);
        }
        self.persist()?;
        Ok(())
    }

    pub fn send_lobby(
        &mut self,
        lobby_id: LobbyId,
        message: impl Into<HydraMessage>,
    ) -> HydraResult<Vec<HydraLobbyEnvelope>> {
        let lobby = self.get_lobby(lobby_id)?;
        if lobby.members.is_empty() {
            return Err(HydraMsgError::InvalidInput("lobby has no members"));
        }
        let message = message.into();
        let packed_message = pack_message(&message)?;
        let lobby_payload = pack_lobby_payload(lobby_id, &packed_message)?;
        let mut envelopes = Vec::with_capacity(lobby.members.len());
        for member in lobby.members {
            let envelope = self.seal_payload_for_contact(member, &lobby_payload)?;
            envelopes.push(HydraLobbyEnvelope {
                recipient: member,
                envelope,
            });
        }
        self.persist()?;
        Ok(envelopes)
    }

    pub fn receive_lobby(
        &mut self,
        envelope: impl AsRef<[u8]>,
    ) -> HydraResult<ReceivedHydraMessage> {
        let (from, lobby_id, packed_message) =
            self.open_lobby_payload_from_contact(envelope.as_ref())?;
        let lobby = self.get_lobby(lobby_id)?;
        if !lobby.members.contains(&from) {
            return Err(HydraMsgError::InvalidInput(
                "lobby message sender is not a member",
            ));
        }
        let message = unpack_message(
            &packed_message,
            from,
            MessageId(self.next_message_id),
            Some(lobby_id),
        )?;
        self.store_message(
            from,
            true,
            message.plaintext.clone(),
            message.attachments.clone(),
        );
        self.persist()?;
        Ok(message)
    }

    pub fn rekey_lobby(&mut self, lobby_id: LobbyId) -> HydraResult<()> {
        let members = self.get_lobby(lobby_id)?.members;
        for member in members {
            if self.sessions.contains_key(&member) {
                let _ = self.rekey_session(member);
            }
        }
        Ok(())
    }

    pub fn close_lobby(&mut self, lobby_id: LobbyId) -> HydraResult<()> {
        self.leave_lobby(lobby_id)
    }

    pub fn export_backup(&self, password: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        let snapshot = self.encode_state_snapshot()?;
        let nonce = random_array::<12>()?;
        let key = backup_key(password.as_ref());
        let ciphertext = RustCryptoBackend::aead_seal(&key, &nonce, BACKUP_MAGIC, &snapshot)?;
        let mut out = Vec::new();
        out.extend_from_slice(BACKUP_MAGIC);
        out.extend_from_slice(hex_encode(&nonce).as_bytes());
        out.push(b'\n');
        out.extend_from_slice(hex_encode(&ciphertext).as_bytes());
        out.push(b'\n');
        Ok(out)
    }

    pub fn import_backup(
        &mut self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<()> {
        let snapshot = decode_backup(bytes.as_ref(), password.as_ref())?;
        self.apply_state_snapshot(&snapshot)?;
        self.persist()?;
        Ok(())
    }

    pub fn verify_backup(&self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        parse_backup_outer(bytes.as_ref()).map(|_| ())
    }

    #[must_use]
    pub fn storage_status(&self) -> HydraStorageStatus {
        HydraStorageStatus {
            data_dir: self.data_dir.clone(),
            identity_count: self.identities.len(),
            contact_count: self.contacts.len(),
            session_count: self.sessions.len(),
            message_count: self.messages.len(),
            lobby_count: self.lobbies.len(),
        }
    }

    pub fn benchmark(&self) -> HydraResult<HydraBenchmarkReport> {
        const ITERATIONS: u32 = 30;
        let mut handshake_total = 0.0;
        let mut send_receive_total = 0.0;
        for _ in 0..ITERATIONS {
            let nonce = random_array::<32>()?;
            let left = IdentityId(random_array::<32>()?);
            let right = IdentityId(random_array::<32>()?);
            let start = Instant::now();
            let (secret, transcript_hash) = derive_facade_handshake_material(nonce, left, right);
            let left_secrets = derive_initial_secrets(&secret, &transcript_hash)?;
            let right_secrets = derive_initial_secrets(&secret, &transcript_hash)?;
            let mut left_session = SessionState::established(
                SessionRole::Initiator,
                transcript_hash,
                left.0,
                right.0,
                left_secrets,
            );
            let mut right_session = SessionState::established(
                SessionRole::Responder,
                transcript_hash,
                right.0,
                left.0,
                right_secrets,
            );
            handshake_total += start.elapsed().as_secs_f64() * 1_000.0;

            let payload = pack_message(&HydraMessage::text("benchmark"))?;
            let start = Instant::now();
            let envelope = left_session.send_data(&payload)?;
            let _ = right_session.receive(&envelope.envelope)?;
            send_receive_total += start.elapsed().as_secs_f64() * 1_000.0;
        }
        Ok(HydraBenchmarkReport {
            suite: "HYDRA1-MK768-M65",
            iterations: ITERATIONS,
            handshake_avg_ms: handshake_total / f64::from(ITERATIONS),
            send_receive_avg_ms: send_receive_total / f64::from(ITERATIONS),
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn state_path(&self) -> PathBuf {
        self.data_dir.join(STATE_FILE_NAME)
    }

    fn load_state(&mut self) -> HydraResult<()> {
        #[cfg(target_arch = "wasm32")]
        {
            return Ok(());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = self.state_path();
            if !path.exists() {
                return Ok(());
            }
            let bytes = fs::read(path)?;
            self.apply_state_snapshot(&bytes)
        }
    }

    fn persist(&self) -> HydraResult<()> {
        #[cfg(target_arch = "wasm32")]
        {
            return Ok(());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let snapshot = self.encode_state_snapshot()?;
            let path = self.state_path();
            let tmp = path.with_extension("tmp");
            fs::write(&tmp, snapshot)?;
            fs::rename(tmp, path)?;
            Ok(())
        }
    }

    fn encode_state_snapshot(&self) -> HydraResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(format!("next_message_id\t{}\n", self.next_message_id).as_bytes());
        for record in self.identities.values() {
            out.extend_from_slice(encode_identity_line(record).as_bytes());
            out.push(b'\n');
        }
        for contact in self.contacts.values() {
            out.extend_from_slice(encode_contact_line(contact).as_bytes());
            out.push(b'\n');
        }
        for message in &self.messages {
            out.extend_from_slice(encode_message_line(message).as_bytes());
            out.push(b'\n');
        }
        for lobby in self.lobbies.values() {
            out.extend_from_slice(encode_lobby_line(lobby).as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }

    fn apply_state_snapshot(&mut self, bytes: &[u8]) -> HydraResult<()> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| HydraMsgError::InvalidEncoding("state snapshot utf-8"))?;
        if !text.starts_with(std::str::from_utf8(STATE_MAGIC).unwrap_or_default()) {
            return Err(HydraMsgError::InvalidEncoding("state snapshot magic"));
        }
        self.identities.clear();
        self.active_id = None;
        self.contacts.clear();
        self.pending_offers.clear();
        self.sessions.clear();
        self.messages.clear();
        self.lobbies.clear();
        self.next_message_id = 1;
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split('\t');
            match parts.next() {
                Some("next_message_id") => {
                    if let Some(value) = parts.next() {
                        self.next_message_id = value
                            .parse()
                            .map_err(|_| HydraMsgError::InvalidEncoding("state next_message_id"))?;
                    }
                }
                Some("identity") => {
                    let record = decode_identity_line(line)?;
                    self.identities.insert(record.id, record);
                }
                Some("contact") => {
                    let contact = decode_contact_line(line)?;
                    self.contacts.insert(contact.id, contact);
                }
                Some("message") => {
                    let message = decode_message_line(line)?;
                    self.next_message_id = self.next_message_id.max(message.id.0.saturating_add(1));
                    self.messages.push(message);
                }
                Some("lobby") => {
                    let lobby = decode_lobby_line(line)?;
                    self.lobbies.insert(lobby.id, lobby);
                }
                _ => return Err(HydraMsgError::InvalidEncoding("state record kind")),
            }
        }
        Ok(())
    }

    fn identity_seed(&self, record: &IdentityRecord, password: &str) -> HydraResult<[u8; 32]> {
        if let Some(seed) = record.seed {
            verify_password(record, password)?;
            return Ok(seed);
        }
        decrypt_seed(record, password)
    }

    fn active_record(&self) -> HydraResult<&IdentityRecord> {
        let id = self.active_id.ok_or(HydraMsgError::IdentityNotFound)?;
        self.identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)
    }

    fn active_unlocked_record(&self) -> HydraResult<&IdentityRecord> {
        let record = self.active_record()?;
        if record.unlocked && record.seed.is_some() {
            Ok(record)
        } else {
            Err(HydraMsgError::InvalidInput("active identity is locked"))
        }
    }

    fn require_contact(&self, contact_id: ContactId) -> HydraResult<&HydraContact> {
        self.contacts
            .get(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)
    }

    fn lobby_invite_members(&self, lobby: &HydraLobby) -> Vec<ContactId> {
        let mut members = Vec::new();
        if let Some(active_id) = self.active_id {
            members.push(ContactId(active_id.0));
        }
        for member in &lobby.members {
            if !members.contains(member) {
                members.push(*member);
            }
        }
        members
    }

    fn normalize_lobby_members_for_local_identity(&self, lobby: &mut HydraLobby) {
        let local_contact_id = self.active_id.map(|id| ContactId(id.0));
        let mut normalized = Vec::new();
        for member in &lobby.members {
            if Some(*member) == local_contact_id {
                continue;
            }
            if !normalized.contains(member) {
                normalized.push(*member);
            }
        }
        lobby.members = normalized;
    }

    fn seal_payload_for_contact(
        &mut self,
        contact_id: ContactId,
        payload: &[u8],
    ) -> HydraResult<HydraEnvelope> {
        let contact = self.require_contact(contact_id)?;
        if contact.blocked {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        if payload.len() > FULL_MAX_CONTENT_SIZE {
            return Err(HydraMsgError::PayloadTooLarge);
        }
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        let outbound = session.state.send_data(payload)?;
        Ok(HydraEnvelope(outbound.envelope))
    }

    fn open_payload_from_contact(&mut self, envelope: &[u8]) -> HydraResult<(ContactId, Vec<u8>)> {
        let matching_contact = self
            .sessions
            .iter_mut()
            .find_map(|(contact_id, session)| {
                if session.closed {
                    return None;
                }
                match session.state.receive(envelope) {
                    Ok(message) => Some(Ok((*contact_id, message.content))),
                    Err(SessionError::AuthenticationFailed) => None,
                    Err(SessionError::ReplayDetected) => Some(Err(HydraMsgError::Session(
                        SessionError::ReplayDetected.to_string(),
                    ))),
                    Err(error) => Some(Err(HydraMsgError::Session(error.to_string()))),
                }
            })
            .ok_or(HydraMsgError::SessionNotFound)??;
        if self
            .contacts
            .get(&matching_contact.0)
            .is_some_and(|contact| contact.blocked)
        {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        Ok(matching_contact)
    }

    fn open_lobby_payload_from_contact(
        &mut self,
        envelope: &[u8],
    ) -> HydraResult<(ContactId, LobbyId, Vec<u8>)> {
        for (contact_id, session) in &mut self.sessions {
            if session.closed {
                continue;
            }
            let snapshot = session.state.export_snapshot();
            match session.state.receive(envelope) {
                Ok(message) => {
                    if self
                        .contacts
                        .get(contact_id)
                        .is_some_and(|contact| contact.blocked)
                    {
                        session.state = SessionState::from_snapshot(snapshot);
                        return Err(HydraMsgError::InvalidInput("contact is blocked"));
                    }
                    match unpack_lobby_payload(&message.content) {
                        Ok((lobby_id, packed_message)) => {
                            return Ok((*contact_id, lobby_id, packed_message));
                        }
                        Err(error) => {
                            session.state = SessionState::from_snapshot(snapshot);
                            return Err(error);
                        }
                    }
                }
                Err(SessionError::AuthenticationFailed) => {}
                Err(SessionError::ReplayDetected) => {
                    return Err(HydraMsgError::Session(
                        SessionError::ReplayDetected.to_string(),
                    ));
                }
                Err(error) => return Err(HydraMsgError::Session(error.to_string())),
            }
        }
        Err(HydraMsgError::SessionNotFound)
    }

    fn store_message(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(path: &str) -> Hydra {
        let _ = std::fs::remove_dir_all(path);
        Hydra::open(path).unwrap()
    }

    #[test]
    fn identity_export_import_roundtrip() {
        let mut hydra = fresh("target/hydra-msg-test-identity");
        let id = hydra.generate_id("pw").unwrap();
        assert_eq!(hydra.list_ids().len(), 1);
        assert_eq!(hydra.get_id(id).unwrap().id(), id);
        hydra.rename_id(id, "main").unwrap();
        assert_eq!(hydra.get_id(id).unwrap().label(), "main");
        let exported = hydra.export_id(id, "pw").unwrap();
        let imported = hydra.import_id(exported, "new-pw").unwrap();
        assert_eq!(id, imported);
        hydra.set_active_id(imported, "new-pw").unwrap();
        assert_eq!(hydra.active_id(), Some(imported));
        hydra.lock_active_id().unwrap();
        assert_eq!(hydra.active_id(), None);
        hydra.unlock_id(imported, "new-pw").unwrap();
        hydra.delete_id(imported, "new-pw").unwrap();
    }

    #[test]
    fn contact_import_export_and_verification_roundtrip() {
        let mut alice = fresh("target/hydra-msg-test-contact-alice");
        let mut bob = fresh("target/hydra-msg-test-contact-bob");
        let alice_id = alice.generate_id("pw").unwrap();
        let bob_id = bob.generate_id("pw").unwrap();
        alice.set_active_id(alice_id, "pw").unwrap();
        bob.set_active_id(bob_id, "pw").unwrap();

        let bob_card = bob.create_contact_card().unwrap();
        let bob_contact = alice.add_contact(bob_card).unwrap();
        let safety = bob_contact.safety_code();
        alice.verify_contact(bob_contact.id(), safety).unwrap();
        assert!(alice.get_contact(bob_contact.id()).unwrap().verified());
        alice.unverify_contact(bob_contact.id()).unwrap();
        assert!(!alice.get_contact(bob_contact.id()).unwrap().verified());
        alice.rename_contact(bob_contact.id(), "Bob").unwrap();
        assert_eq!(alice.get_contact(bob_contact.id()).unwrap().label(), "Bob");

        let exported = alice.export_contacts().unwrap();
        let mut imported = fresh("target/hydra-msg-test-contact-import");
        imported.import_contacts(exported).unwrap();
        assert_eq!(imported.list_contacts().len(), 1);
        assert_eq!(
            imported.get_contact(bob_contact.id()).unwrap().label(),
            "Bob"
        );
        assert!(!imported.get_contact(bob_contact.id()).unwrap().verified());
        imported.block_contact(bob_contact.id()).unwrap();
        assert!(imported.get_contact(bob_contact.id()).unwrap().blocked());
        imported.unblock_contact(bob_contact.id()).unwrap();
        assert!(!imported.get_contact(bob_contact.id()).unwrap().blocked());
    }

    #[test]
    fn contact_handshake_and_attachment_roundtrip() {
        let mut alice = fresh("target/hydra-msg-test-alice");
        let mut bob = fresh("target/hydra-msg-test-bob");
        let alice_id = alice.generate_id("pw").unwrap();
        let bob_id = bob.generate_id("pw").unwrap();
        alice.set_active_id(alice_id, "pw").unwrap();
        bob.set_active_id(bob_id, "pw").unwrap();

        let alice_card = alice.create_contact_card().unwrap();
        let bob_card = bob.create_contact_card().unwrap();
        let alice_contact = bob.add_contact(alice_card).unwrap();
        let bob_contact = alice.add_contact(bob_card).unwrap();

        let offer = alice.init_handshake(bob_contact.id()).unwrap();
        let answer = bob.reply_handshake(offer).unwrap();
        alice.finish_handshake(answer).unwrap();
        assert_eq!(
            alice.session_status(bob_contact.id()).unwrap(),
            HydraSessionStatus::Active
        );
        assert_eq!(
            bob.session_status(alice_contact.id()).unwrap(),
            HydraSessionStatus::Active
        );

        let bytes_attachment = HydraAttachment::from_bytes(b"anonymous-bytes".to_vec()).unwrap();
        assert_eq!(bytes_attachment.filename(), "attachment.bin");
        assert!(bytes_attachment.is_bytes());

        let named_attachment = HydraAttachment::from_bytes(b"named-bytes".to_vec())
            .unwrap()
            .with_filename("note.bin")
            .unwrap();

        let envelope = alice
            .send(
                bob_contact.id(),
                HydraMessage {
                    plaintext: b"hello".to_vec(),
                    attachments: vec![bytes_attachment, named_attachment],
                },
            )
            .unwrap();
        let received = bob.receive(envelope).unwrap();
        assert_eq!(received.from(), alice_contact.id());
        assert_eq!(received.text().unwrap(), "hello");
        assert_eq!(received.attachments()[0].filename(), "attachment.bin");
        assert_eq!(received.attachments()[0].bytes(), b"anonymous-bytes");
        assert_eq!(received.attachments()[1].filename(), "note.bin");
        assert_eq!(received.attachments()[1].bytes(), b"named-bytes");
    }

    #[test]
    fn fluent_message_attachment_roundtrip() {
        let mut alice = fresh("target/hydra-msg-test-fluent-alice");
        let mut bob = fresh("target/hydra-msg-test-fluent-bob");
        let alice_id = alice.generate_id("pw").unwrap();
        let bob_id = bob.generate_id("pw").unwrap();
        alice.set_active_id(alice_id, "pw").unwrap();
        bob.set_active_id(bob_id, "pw").unwrap();
        let alice_contact = bob
            .add_contact(alice.create_contact_card().unwrap())
            .unwrap();
        let bob_contact = alice
            .add_contact(bob.create_contact_card().unwrap())
            .unwrap();
        let answer = bob
            .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
            .unwrap();
        alice.finish_handshake(answer).unwrap();

        let envelope = alice
            .send(
                bob_contact.id(),
                HydraMessage::text("hello")
                    .attach_bytes("data.bin", b"bytes".to_vec())
                    .unwrap(),
            )
            .unwrap();
        let received = bob.receive(envelope).unwrap();
        assert_eq!(received.from(), alice_contact.id());
        assert_eq!(received.text().unwrap(), "hello");
        assert_eq!(received.attachments()[0].filename(), "data.bin");
        assert!(received.attachments()[0].is_bytes());
    }

    #[test]
    fn lobby_backup_storage_and_benchmark_surface_exists() {
        let mut hydra = fresh("target/hydra-msg-test-lobby");
        let id = hydra.generate_id("pw").unwrap();
        hydra.set_active_id(id, "pw").unwrap();
        let lobby = hydra
            .create_lobby(HydraLobbyPolicy::new("test", 4))
            .unwrap();
        let invite = hydra.create_lobby_invite(lobby.id()).unwrap();
        let joined = hydra.join_lobby(invite).unwrap();
        assert_eq!(joined.id(), lobby.id());
        assert_eq!(hydra.list_lobbies().len(), 1);
        assert!(hydra.lobby_members(lobby.id()).unwrap().is_empty());
        hydra.rekey_lobby(lobby.id()).unwrap();
        let backup = hydra.export_backup("pw").unwrap();
        hydra.verify_backup(&backup).unwrap();
        hydra.import_backup(&backup, "pw").unwrap();
        let status = hydra.storage_status();
        assert_eq!(status.identity_count, 1);
        let report = hydra.benchmark().unwrap();
        assert_eq!(report.iterations, 30);
        hydra.close_lobby(lobby.id()).unwrap();
    }

    #[test]
    fn lobby_send_receive_uses_recipient_tagged_envelopes_and_membership_checks() {
        let mut alice = fresh("target/hydra-msg-test-lobby-alice");
        let mut bob = fresh("target/hydra-msg-test-lobby-bob");
        let alice_id = alice.generate_id("pw").unwrap();
        let bob_id = bob.generate_id("pw").unwrap();
        alice.set_active_id(alice_id, "pw").unwrap();
        bob.set_active_id(bob_id, "pw").unwrap();

        let alice_contact = bob
            .add_contact(alice.create_contact_card().unwrap())
            .unwrap();
        let bob_contact = alice
            .add_contact(bob.create_contact_card().unwrap())
            .unwrap();
        let answer = bob
            .reply_handshake(alice.init_handshake(bob_contact.id()).unwrap())
            .unwrap();
        alice.finish_handshake(answer).unwrap();

        let lobby = alice
            .create_lobby(HydraLobbyPolicy::new("party", 4))
            .unwrap();
        alice
            .add_lobby_member(lobby.id(), bob_contact.id())
            .unwrap();
        let invite = alice.create_lobby_invite(lobby.id()).unwrap();
        let joined = bob.join_lobby(invite).unwrap();
        assert_eq!(joined.id(), lobby.id());
        assert_eq!(
            bob.lobby_members(joined.id()).unwrap(),
            vec![alice_contact.id()]
        );

        let outbound = alice
            .send_lobby(
                lobby.id(),
                HydraMessage::text("hello lobby")
                    .attach_bytes("lobby.bin", b"payload".to_vec())
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].recipient(), bob_contact.id());
        let received = bob.receive_lobby(outbound[0].envelope().clone()).unwrap();
        assert_eq!(received.from(), alice_contact.id());
        assert_eq!(received.lobby_id(), Some(joined.id()));
        assert_eq!(received.text().unwrap(), "hello lobby");
        assert_eq!(received.attachments()[0].filename(), "lobby.bin");

        let normal = alice.send(bob_contact.id(), "not a lobby message").unwrap();
        assert!(bob.receive_lobby(normal.clone()).is_err());
        assert_eq!(
            bob.receive(normal).unwrap().text().unwrap(),
            "not a lobby message"
        );
    }

    #[test]
    fn native_storage_persists_locked_identity_contacts_messages_and_lobbies() {
        let path = "target/hydra-msg-test-persistence";
        let mut hydra = fresh(path);
        let id = hydra.generate_id("pw").unwrap();
        hydra.set_active_id(id, "pw").unwrap();
        let card = hydra.create_contact_card().unwrap();
        let contact = hydra.add_contact(card).unwrap();
        hydra.rename_contact(contact.id(), "self-contact").unwrap();
        hydra.store_message(
            contact.id(),
            true,
            b"persisted".to_vec(),
            vec![HydraAttachment::from_named_bytes("persisted.bin", b"bytes".to_vec()).unwrap()],
        );
        let lobby = hydra
            .create_lobby(HydraLobbyPolicy::new("persisted lobby", 3))
            .unwrap();
        hydra.add_lobby_member(lobby.id(), contact.id()).unwrap();
        hydra.persist().unwrap();

        let mut reopened = Hydra::open(path).unwrap();
        assert_eq!(reopened.list_ids().len(), 1);
        assert_eq!(reopened.active_id(), None);
        assert!(!reopened.get_id(id).unwrap().unlocked());
        reopened.set_active_id(id, "pw").unwrap();
        assert_eq!(reopened.list_contacts().len(), 1);
        assert_eq!(
            reopened.get_contact(contact.id()).unwrap().label(),
            "self-contact"
        );
        let messages = reopened.list_messages(contact.id());
        assert_eq!(messages.len(), 1);
        let message = reopened.get_message(messages[0]).unwrap();
        assert_eq!(message.text().unwrap(), "persisted");
        assert_eq!(message.attachments()[0].filename(), "persisted.bin");
        assert_eq!(reopened.list_lobbies().len(), 1);
    }

    #[test]
    fn encrypted_backup_requires_password_and_restores_state() {
        let mut hydra = fresh("target/hydra-msg-test-backup-source");
        let id = hydra.generate_id("id-pw").unwrap();
        hydra.set_active_id(id, "id-pw").unwrap();
        let contact = hydra
            .add_contact(hydra.create_contact_card().unwrap())
            .unwrap();
        hydra.store_message(contact.id(), true, b"backup-message".to_vec(), Vec::new());
        hydra.persist().unwrap();
        let backup = hydra.export_backup("backup-pw").unwrap();
        hydra.verify_backup(&backup).unwrap();

        let mut restored = fresh("target/hydra-msg-test-backup-restored");
        assert!(restored.import_backup(&backup, "wrong-pw").is_err());
        restored.import_backup(&backup, "backup-pw").unwrap();
        assert_eq!(restored.list_ids().len(), 1);
        assert_eq!(restored.list_contacts().len(), 1);
        assert_eq!(restored.list_messages(contact.id()).len(), 1);
        restored.set_active_id(id, "id-pw").unwrap();
    }
}
