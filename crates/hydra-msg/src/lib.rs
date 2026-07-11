//! Simple public HYDRA-MSG facade.
//!
//! This crate is the app developer entry point. It intentionally hides crypto,
//! envelope, ratchet, chunking, and wire-format internals behind a small API.
//! Carriers such as WebRTC, files, HTTP, QR codes, relays, libp2p, Kaspa
//! pointers, and mailboxes only move the opaque bytes returned by this crate.

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::PathBuf,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::persistence::native_store::NativeProfileLock;
use hydra_crypto::SecretBytes;
use hydra_session::SessionError;

#[path = "api/anonymous_auth.rs"]
mod anonymous_auth;
#[path = "api/benchmark.rs"]
mod benchmark;
#[cfg(target_arch = "wasm32")]
#[path = "browser/persistence.rs"]
mod browser_persistence;
mod codec;
#[path = "api/contacts.rs"]
mod contacts;
#[path = "envelope/limits.rs"]
mod envelope_limits;
mod handshake;
#[path = "api/identity.rs"]
mod identity;
mod limits;
#[path = "api/lobbies.rs"]
mod lobbies;
#[path = "lobby/delivery.rs"]
mod lobby_delivery;
#[path = "lobby/routing.rs"]
mod lobby_routing;
mod messages;
mod packet_fragments;
mod persistence;
#[path = "api/receive.rs"]
mod receive;
#[path = "api/storage.rs"]
mod storage;
mod time;

pub use anonymous_auth::{
    HydraAnonymousAuthGrant, HydraAnonymousAuthNullifier, HydraAnonymousAuthPolicy,
    HydraAnonymousAuthToken,
};
pub use benchmark::HydraBenchmarkReport;
pub use contacts::{ContactId, HydraContact, HydraOneTimeContactCard};
pub use handshake::{HandshakeAnswer, HandshakeOffer, HydraEnvelope, HydraSessionStatus};
pub use identity::{HydraIdentitySummary, IdentityId};
pub use lobbies::{
    HydraLobby, HydraLobbyInvite, HydraLobbyPolicy, HydraOneTimeLobbyInvite, LobbyId,
};
pub use lobby_routing::{HydraLobbyEnvelope, HydraLobbyRoutingHint};
pub use messages::{
    HydraAttachment, HydraAttachmentSource, HydraMessage, MessageId, ReceivedHydraMessage,
};
pub use persistence::{HydraStorageDebugStatus, HydraStorageStatus};

use codec::PasswordKdfRecord;
use handshake::{PendingOffer, SessionRecord};
use identity::IdentityRecord;
use messages::{MessageUsage, StoredMessage};
use packet_fragments::{PendingFragmentKey, PendingInboundFragments};

pub(crate) const CONTACT_CARD_MAGIC: &str = "HYDRA-MSG-CONTACT";
pub(crate) const ID_EXPORT_MAGIC: &[u8] = b"HYDRA-MSG-ID\n";
pub(crate) const OFFER_MAGIC: &[u8] = b"HYDRA-MSG-OFFER\n";
pub(crate) const ANSWER_MAGIC: &[u8] = b"HYDRA-MSG-ANSWER\n";
pub(crate) const PAYLOAD_MAGIC: &[u8] = b"HYDRA-MSG-PAYLOAD\n";
pub(crate) const LOBBY_INVITE_MAGIC: &str = "HYDRA-MSG-LOBBY-INVITE";
pub(crate) const LOBBY_PAYLOAD_MAGIC: &[u8] = b"HYDRA-MSG-LOBBY-PAYLOAD\n";
pub(crate) const AUTH_TOKEN_MAGIC: &str = "HYDRA-MSG-AUTH-TOKEN";
pub(crate) const BACKUP_MAGIC: &[u8] = b"HYDRA-MSG-BACKUP\n";
pub(crate) const STATE_SNAPSHOT_MAGIC: &[u8] = b"HYDRA-MSG-STATE-SNAPSHOT\n";
pub(crate) const STATE_MAGIC: &[u8] = b"HYDRA-MSG-STATE\n";
pub(crate) const CONTACTS_MAGIC: &[u8] = b"HYDRA-MSG-CONTACTS\n";
pub(crate) const MESSAGES_MAGIC: &[u8] = b"HYDRA-MSG-MESSAGES\n";
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const STATE_FILE_NAME: &str = "state.hydra";
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const STATE_ROLLBACK_FILE_NAME: &str = "state.hydra.rollback";

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
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) _native_profile_lock: Option<NativeProfileLock>,
    pub(crate) identities: HashMap<IdentityId, IdentityRecord>,
    pub(crate) active_id: Option<IdentityId>,
    pub(crate) contacts: HashMap<ContactId, HydraContact>,
    pub(crate) pending_offers: HashMap<[u8; 32], PendingOffer>,
    pub(crate) sessions: HashMap<ContactId, SessionRecord>,
    pub(crate) receive_routes: HashMap<[u8; 16], Vec<ContactId>>,
    pub(crate) session_route_tags: HashMap<ContactId, Vec<[u8; 16]>>,
    pub(crate) messages: Vec<StoredMessage>,
    pub(crate) message_usage: HashMap<ContactId, MessageUsage>,
    pub(crate) stored_message_bytes: usize,
    pub(crate) next_message_id: u64,
    pub(crate) lobbies: HashMap<LobbyId, HydraLobby>,
    pub(crate) anonymous_auth_secret: SecretBytes<32>,
    pub(crate) anonymous_auth_spent: Vec<HydraAnonymousAuthNullifier>,
    pub(crate) anonymous_auth_spent_index: HashSet<HydraAnonymousAuthNullifier>,
    pub(crate) state_key: SecretBytes<32>,
    pub(crate) state_kdf: PasswordKdfRecord,
    pub(crate) state_generation: u64,
    pub(crate) packet_size: usize,
    pub(crate) pending_fragments: HashMap<PendingFragmentKey, PendingInboundFragments>,
}

#[cfg(test)]
#[path = "tests/adversarial_protocol.rs"]
mod adversarial_protocol_tests;
#[cfg(test)]
#[path = "tests/anonymous_auth.rs"]
mod anonymous_auth_tests;
#[cfg(test)]
#[path = "tests/api_freeze.rs"]
mod api_freeze_tests;
#[cfg(test)]
#[path = "tests/crash_consistency.rs"]
mod crash_consistency_tests;
#[cfg(test)]
#[path = "tests/domain_separation.rs"]
mod domain_separation_tests;

#[cfg(test)]
#[path = "tests/envelope_limits.rs"]
mod envelope_limits_tests;
#[cfg(test)]
#[path = "tests/handshake.rs"]
mod handshake_tests;
#[cfg(test)]
#[path = "tests/lobby_routing.rs"]
mod lobby_routing_tests;

#[cfg(test)]
#[path = "tests/lifecycle_edges.rs"]
mod lifecycle_edges_tests;
#[cfg(test)]
#[path = "tests/limit_boundaries.rs"]
mod limit_boundaries_tests;
#[cfg(test)]
#[path = "tests/native_concurrency.rs"]
mod native_concurrency_tests;
#[cfg(test)]
#[path = "tests/public_api_misuse.rs"]
mod public_api_misuse_tests;
#[cfg(test)]
#[path = "tests/storage_chunks.rs"]
mod storage_chunk_tests;

#[cfg(test)]
#[path = "tests/persistence.rs"]
mod persistence_tests;
#[cfg(test)]
#[path = "tests/resource_limits.rs"]
mod resource_limits_tests;
#[cfg(test)]
#[path = "tests/storage.rs"]
mod storage_tests;
