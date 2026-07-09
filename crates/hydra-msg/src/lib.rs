//! Simple public HYDRA-MSG facade.
//!
//! This crate is the app developer entry point. It intentionally hides crypto,
//! envelope, ratchet, chunking, and wire-format internals behind a small API.
//! Carriers such as WebRTC, files, HTTP, QR codes, relays, libp2p, Kaspa
//! pointers, and mailboxes only move the opaque bytes returned by this crate.

#![forbid(unsafe_code)]

use std::{collections::HashMap, fmt, path::PathBuf};

use hydra_crypto::SecretBytes;
use hydra_session::SessionError;

mod benchmark;
mod codec;
mod contacts;
mod handshake;
mod identity;
mod lobbies;
mod messages;
mod storage;

pub use benchmark::HydraBenchmarkReport;
pub use contacts::{ContactId, HydraContact, HydraOneTimeContactCard};
pub use handshake::{HandshakeAnswer, HandshakeOffer, HydraEnvelope, HydraSessionStatus};
pub use identity::{HydraIdentitySummary, IdentityId};
pub use lobbies::{
    HydraLobby, HydraLobbyEnvelope, HydraLobbyInvite, HydraLobbyPolicy, HydraOneTimeLobbyInvite,
    LobbyId,
};
pub use messages::{
    HydraAttachment, HydraAttachmentSource, HydraMessage, MessageId, ReceivedHydraMessage,
};
pub use storage::HydraStorageStatus;

use codec::PasswordKdfRecord;
use handshake::{PendingOffer, SessionRecord};
use identity::IdentityRecord;
use messages::StoredMessage;

pub(crate) const CONTACT_CARD_MAGIC: &str = "HYDRA-MSG-CONTACT-V2";
pub(crate) const ID_EXPORT_MAGIC: &[u8] = b"HYDRA-MSG-ID-V1\n";
pub(crate) const OFFER_MAGIC: &[u8] = b"HYDRA-MSG-OFFER-V1\n";
pub(crate) const ANSWER_MAGIC: &[u8] = b"HYDRA-MSG-ANSWER-V1\n";
pub(crate) const PAYLOAD_MAGIC: &[u8] = b"HYDRA-MSG-PAYLOAD-V1\n";
pub(crate) const LOBBY_INVITE_MAGIC: &str = "HYDRA-MSG-LOBBY-INVITE-V2";
pub(crate) const LOBBY_PAYLOAD_MAGIC: &[u8] = b"HYDRA-MSG-LOBBY-PAYLOAD-V1\n";
pub(crate) const BACKUP_MAGIC: &[u8] = b"HYDRA-MSG-BACKUP-V1\n";
pub(crate) const STATE_SNAPSHOT_MAGIC: &[u8] = b"HYDRA-MSG-STATE-SNAPSHOT-V2\n";
pub(crate) const STATE_V2_MAGIC: &[u8] = b"HYDRA-MSG-STATE-V2\n";
pub(crate) const CONTACTS_MAGIC: &[u8] = b"HYDRA-MSG-CONTACTS-V1\n";
pub(crate) const MESSAGES_MAGIC: &[u8] = b"HYDRA-MSG-MESSAGES-V1\n";
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const STATE_FILE_NAME: &str = "state-v2.hydra";
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const STATE_ROLLBACK_FILE_NAME: &str = "state-v2.hydra.rollback";

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

/// Main public HYDRA facade.
pub struct Hydra {
    pub(crate) data_dir: PathBuf,
    pub(crate) identities: HashMap<IdentityId, IdentityRecord>,
    pub(crate) active_id: Option<IdentityId>,
    pub(crate) contacts: HashMap<ContactId, HydraContact>,
    pub(crate) pending_offers: HashMap<[u8; 32], PendingOffer>,
    pub(crate) sessions: HashMap<ContactId, SessionRecord>,
    pub(crate) messages: Vec<StoredMessage>,
    pub(crate) next_message_id: u64,
    pub(crate) lobbies: HashMap<LobbyId, HydraLobby>,
    pub(crate) state_key: SecretBytes<32>,
    pub(crate) state_kdf: PasswordKdfRecord,
    pub(crate) state_generation: u64,
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod handshake_tests;
#[cfg(test)]
mod storage_tests;
