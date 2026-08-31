use crate::{
    codec::{HandshakeMaterial, ParsedHandshakeOffer},
    time::HydraInstant,
    ContactId, IdentityId,
};
use hydra_crypto::{MlKemDecapsulationKey, X25519SecretKey};
use hydra_session::SessionState;

/// Opaque canonical INIT bootstrap envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeOffer(pub(crate) Vec<u8>);

/// Opaque canonical RESP bootstrap envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeAnswer(pub(crate) Vec<u8>);

/// Opaque authenticated FINISH Lite envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeFinish(pub(crate) Vec<u8>);

/// Opaque encrypted HYDRA envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraEnvelope(pub(crate) Vec<u8>);

macro_rules! opaque_bytes {
    ($ty:ty) => {
        impl $ty {
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
        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
}

opaque_bytes!(HandshakeOffer);
opaque_bytes!(HandshakeAnswer);
opaque_bytes!(HandshakeFinish);
opaque_bytes!(HydraEnvelope);

/// Session status exposed to normal developers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HydraSessionStatus {
    Missing,
    Pending,
    Active,
    Closed,
}

pub(crate) struct SessionRecord {
    pub(crate) state: SessionState,
    pub(crate) closed: bool,
    pub(crate) outbound_messages: u64,
    pub(crate) rollback_generation_floor: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakePurpose {
    Standard,
    SessionRefresh,
}

pub(crate) struct PendingOffer {
    pub(crate) contact_id: ContactId,
    pub(crate) offer_bytes: Vec<u8>,
    pub(crate) local_identity_id: IdentityId,
    pub(crate) offer: ParsedHandshakeOffer,
    pub(crate) x25519_secret: X25519SecretKey,
    pub(crate) kem_decapsulation_key: MlKemDecapsulationKey,
    pub(crate) created_at: HydraInstant,
    pub(crate) purpose: HandshakePurpose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct AcceptedInitKey {
    pub(crate) initiator_fingerprint: [u8; 32],
    pub(crate) init_nonce: [u8; 32],
    pub(crate) init_hash: [u8; 64],
}

pub(crate) struct ResponderCandidate {
    pub(crate) material: HandshakeMaterial,
}

pub(crate) struct AcceptedInit {
    pub(crate) contact_id: ContactId,
    pub(crate) local_identity_id: IdentityId,
    pub(crate) response: Vec<u8>,
    pub(crate) finish_route_tag: [u8; 16],
    pub(crate) purpose: HandshakePurpose,
    pub(crate) candidate: Option<ResponderCandidate>,
    pub(crate) accepted_finish_hash: Option<[u8; 32]>,
    pub(crate) created_at: HydraInstant,
}
