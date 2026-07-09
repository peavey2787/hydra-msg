use crate::{ContactId, HydraEnvelope};

/// Opaque lobby routing hint for apps/carriers that support mailbox-style routing.
///
/// This value is intentionally not cryptographic authority. The receiver accepts or
/// rejects the encrypted HYDRA envelope based on session authentication, not this
/// carrier-visible hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HydraLobbyRoutingHint(pub(crate) [u8; 32]);

impl HydraLobbyRoutingHint {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Recipient-tagged lobby envelope returned by `send_lobby`.
///
/// The envelope bytes are still opaque HYDRA bytes. `recipient()` is a direct
/// app-local routing hint for applications that already know the contact. It is
/// not anonymous routing and must not be treated as authentication. Apps/carriers
/// that can route through opaque mailbox aliases should use `routing_hint()`
/// instead; the hint is randomized per encrypted copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobbyEnvelope {
    pub(crate) recipient: ContactId,
    pub(crate) routing_hint: HydraLobbyRoutingHint,
    pub(crate) envelope: HydraEnvelope,
}

impl HydraLobbyEnvelope {
    #[must_use]
    pub const fn recipient(&self) -> ContactId {
        self.recipient
    }

    #[must_use]
    pub const fn routing_hint(&self) -> HydraLobbyRoutingHint {
        self.routing_hint
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

    #[must_use]
    pub fn into_routed_parts(self) -> (ContactId, HydraLobbyRoutingHint, HydraEnvelope) {
        (self.recipient, self.routing_hint, self.envelope)
    }
}
