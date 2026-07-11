use crate::{codec::ParsedHandshakeOffer, time::HydraInstant, ContactId};
use hydra_crypto::{MlKemDecapsulationKey, X25519SecretKey};
use hydra_session::SessionState;

/// Opaque handshake offer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeOffer(pub(crate) Vec<u8>);

/// Opaque handshake answer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeAnswer(pub(crate) Vec<u8>);

/// Opaque encrypted HYDRA envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraEnvelope(pub(crate) Vec<u8>);

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

/// Session status exposed to normal developers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HydraSessionStatus {
    Missing,
    Active,
    Closed,
}

pub(crate) struct SessionRecord {
    pub(crate) state: SessionState,
    pub(crate) closed: bool,
}

pub(crate) struct PendingOffer {
    pub(crate) contact_id: ContactId,
    pub(crate) offer: ParsedHandshakeOffer,
    pub(crate) x25519_secret: X25519SecretKey,
    pub(crate) kem_decapsulation_key: MlKemDecapsulationKey,
    pub(crate) created_at: HydraInstant,
}
