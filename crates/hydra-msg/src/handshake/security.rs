use crate::{
    codec::decode_handshake_offer, handshake::HandshakePurpose, ContactId, HandshakeAnswer,
    HandshakeOffer, Hydra, HydraMsgError, HydraResult,
};

const RATCHET_ONLY_SNAPSHOT_VALUE: &str = "ratchet-only";

/// Controls how many outbound logical application messages may use one
/// established pairwise session before the SDK requires a fresh authenticated
/// hybrid handshake.
///
/// Every established session already advances a one-way symmetric ratchet for
/// each encrypted envelope and erases old message keys, protecting prior
/// messages after erasure. A finite interval additionally forces the app to
/// replace the current session with newly contributed X25519 and ML-KEM
/// handshake material before it can send more logical messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HydraSessionSecurityPolicy {
    max_outbound_messages_per_session: Option<u64>,
}

impl HydraSessionSecurityPolicy {
    /// Keep the normal per-envelope ratchet without forcing periodic fresh
    /// hybrid handshakes.
    #[must_use]
    pub const fn ratchet_only() -> Self {
        Self {
            max_outbound_messages_per_session: None,
        }
    }

    /// Require a fresh authenticated hybrid session after every outbound
    /// logical application message.
    #[must_use]
    pub const fn fresh_session_every_message() -> Self {
        Self {
            max_outbound_messages_per_session: Some(1),
        }
    }

    /// Require a fresh authenticated hybrid session after exactly `messages`
    /// outbound logical application messages.
    pub fn every_messages(messages: u64) -> HydraResult<Self> {
        if messages == 0 {
            return Err(HydraMsgError::InvalidInput(
                "session refresh interval must be at least one message",
            ));
        }
        Ok(Self {
            max_outbound_messages_per_session: Some(messages),
        })
    }

    #[must_use]
    pub const fn max_outbound_messages_per_session(self) -> Option<u64> {
        self.max_outbound_messages_per_session
    }

    pub(crate) fn snapshot_value(self) -> String {
        match self.max_outbound_messages_per_session {
            Some(limit) => limit.to_string(),
            None => RATCHET_ONLY_SNAPSHOT_VALUE.to_owned(),
        }
    }

    pub(crate) fn from_snapshot_value(value: &str) -> HydraResult<Self> {
        if value == RATCHET_ONLY_SNAPSHOT_VALUE {
            return Ok(Self::ratchet_only());
        }
        let interval = value
            .parse::<u64>()
            .map_err(|_| HydraMsgError::InvalidEncoding("session security policy"))?;
        Self::every_messages(interval)
            .map_err(|_| HydraMsgError::InvalidEncoding("session security policy"))
    }
}

impl Default for HydraSessionSecurityPolicy {
    fn default() -> Self {
        Self::ratchet_only()
    }
}

/// Current send-side fresh-session cadence for an established contact session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HydraSessionSecurityStatus {
    policy: HydraSessionSecurityPolicy,
    outbound_messages_in_session: u64,
    refresh_required: bool,
}

impl HydraSessionSecurityStatus {
    #[must_use]
    pub const fn policy(self) -> HydraSessionSecurityPolicy {
        self.policy
    }

    #[must_use]
    pub const fn outbound_messages_in_session(self) -> u64 {
        self.outbound_messages_in_session
    }

    #[must_use]
    pub const fn refresh_required(self) -> bool {
        self.refresh_required
    }

    #[must_use]
    pub const fn remaining_messages(self) -> Option<u64> {
        match self.policy.max_outbound_messages_per_session {
            Some(limit) => Some(limit.saturating_sub(self.outbound_messages_in_session)),
            None => None,
        }
    }
}

impl Hydra {
    /// Set the send-side fresh-session interval for a contact. `messages == 0`
    /// selects the default ratchet-only mode; any positive value requires a
    /// fresh authenticated hybrid session after that many outbound logical
    /// application messages.
    pub fn set_session_refresh_interval(
        &mut self,
        contact_id: ContactId,
        messages: u64,
    ) -> HydraResult<()> {
        let policy = if messages == 0 {
            HydraSessionSecurityPolicy::ratchet_only()
        } else {
            HydraSessionSecurityPolicy::every_messages(messages)?
        };
        self.set_session_security_policy(contact_id, policy)
    }

    /// Persist the send-side fresh-session cadence for a contact.
    pub fn set_session_security_policy(
        &mut self,
        contact_id: ContactId,
        policy: HydraSessionSecurityPolicy,
    ) -> HydraResult<()> {
        self.require_contact(contact_id)?;
        let previous = self.session_security_policies.insert(contact_id, policy);
        if let Err(error) = self.persist() {
            match previous {
                Some(previous) => {
                    self.session_security_policies.insert(contact_id, previous);
                }
                None => {
                    self.session_security_policies.remove(&contact_id);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    /// Restore the default ratchet-only policy for a contact.
    pub fn clear_session_security_policy(&mut self, contact_id: ContactId) -> HydraResult<()> {
        self.require_contact(contact_id)?;
        let previous = self.session_security_policies.remove(&contact_id);
        if let Err(error) = self.persist() {
            if let Some(previous) = previous {
                self.session_security_policies.insert(contact_id, previous);
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn session_security_policy(
        &self,
        contact_id: ContactId,
    ) -> HydraResult<HydraSessionSecurityPolicy> {
        self.require_contact(contact_id)?;
        Ok(self
            .session_security_policies
            .get(&contact_id)
            .copied()
            .unwrap_or_default())
    }

    pub fn session_security_status(
        &self,
        contact_id: ContactId,
    ) -> HydraResult<HydraSessionSecurityStatus> {
        let policy = self.session_security_policy(contact_id)?;
        let session = self
            .sessions
            .get(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        let refresh_required = policy
            .max_outbound_messages_per_session
            .is_some_and(|limit| session.outbound_messages >= limit);
        Ok(HydraSessionSecurityStatus {
            policy,
            outbound_messages_in_session: session.outbound_messages,
            refresh_required,
        })
    }

    /// Start a fresh authenticated hybrid handshake for an already-established
    /// contact. The caller must transport the returned offer to the peer and
    /// pause application sends until the replacement handshake completes.
    pub fn begin_session_refresh(&mut self, contact_id: ContactId) -> HydraResult<HandshakeOffer> {
        let session = self
            .sessions
            .get(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        self.init_handshake_for(contact_id, HandshakePurpose::SessionRefresh)
    }

    /// Answer a fresh-session offer from a contact with an existing active
    /// session. This installs the responder side of the replacement session.
    pub fn reply_session_refresh(
        &mut self,
        offer: impl AsRef<[u8]>,
    ) -> HydraResult<HandshakeAnswer> {
        let parsed = decode_handshake_offer(offer.as_ref())?;
        let contact_id = ContactId(parsed.peer_id.0);
        let session = self
            .sessions
            .get(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        self.reply_handshake(offer)
    }

    /// Finish and install the initiator side of a replacement session.
    pub fn finish_session_refresh(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<()> {
        self.finish_handshake_for(answer, HandshakePurpose::SessionRefresh)
    }

    pub(crate) fn reject_send_when_refresh_required(
        &self,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        let policy = self.session_security_policy(contact_id)?;
        let session = self
            .sessions
            .get(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if policy
            .max_outbound_messages_per_session
            .is_some_and(|limit| session.outbound_messages >= limit)
        {
            return Err(HydraMsgError::SessionRefreshRequired);
        }
        if session.outbound_messages == u64::MAX {
            return Err(HydraMsgError::InvalidInput(
                "session outbound message counter exhausted",
            ));
        }
        Ok(())
    }

    pub(crate) fn record_outbound_application_message(
        &mut self,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        session.outbound_messages += 1;
        Ok(())
    }
}
