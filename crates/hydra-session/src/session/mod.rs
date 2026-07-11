use hydra_core::{
    protocol::replay::{ReplayWindow, ReplayWindowSnapshot},
    types::ContentKind,
    MAX_SKIP,
};
use hydra_crypto::SecretBytes;

use crate::{
    key_derivation::InitialSessionSecrets,
    ratchet::{derive_step, DirectionChain, DirectionChainSnapshot},
    skipped_keys::{SkippedKeyStore, SkippedMessageKeySnapshot},
};

mod envelope_bounds;
mod lifecycle;
mod receive;
mod refresh_state;
mod send;
mod snapshot;

#[cfg(any(test, feature = "test-support"))]
mod test_support;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    InitiatorToResponder,
    ResponderToInitiator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Established,
    Refreshing,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshIdDecision {
    Accepted,
    ReplacedLocal,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutboundMessage {
    pub index: u64,
    pub envelope: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub index: u64,
    pub content_kind: ContentKind,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStateSnapshot {
    pub role: SessionRole,
    pub phase: SessionPhase,
    pub session_id: [u8; 32],
    pub transcript_hash: [u8; 64],
    pub local_identity_fingerprint: [u8; 32],
    pub remote_identity_fingerprint: [u8; 32],
    pub refresh_root: [u8; 32],
    pub sending_chain: DirectionChainSnapshot,
    pub receiving_chain: DirectionChainSnapshot,
    pub skipped_keys: Vec<SkippedMessageKeySnapshot>,
    pub replay: ReplayWindowSnapshot,
    pub active_refresh_id: Option<[u8; 32]>,
}

pub struct SessionState {
    role: SessionRole,
    phase: SessionPhase,
    session_id: [u8; 32],
    transcript_hash: [u8; 64],
    local_identity_fingerprint: [u8; 32],
    remote_identity_fingerprint: [u8; 32],
    refresh_root: SecretBytes<32>,
    sending_chain: DirectionChain,
    receiving_chain: DirectionChain,
    skipped_keys: SkippedKeyStore,
    replay: ReplayWindow,
    active_refresh_id: Option<[u8; 32]>,
}

impl SessionState {
    #[must_use]
    pub fn established(
        role: SessionRole,
        transcript_hash: [u8; 64],
        local_identity_fingerprint: [u8; 32],
        remote_identity_fingerprint: [u8; 32],
        secrets: InitialSessionSecrets,
    ) -> Self {
        let (sending_chain, receiving_chain) = match role {
            SessionRole::Initiator => (
                DirectionChain::new(secrets.chain_i2r),
                DirectionChain::new(secrets.chain_r2i),
            ),
            SessionRole::Responder => (
                DirectionChain::new(secrets.chain_r2i),
                DirectionChain::new(secrets.chain_i2r),
            ),
        };
        Self {
            role,
            phase: SessionPhase::Established,
            session_id: secrets.session_id,
            transcript_hash,
            local_identity_fingerprint,
            remote_identity_fingerprint,
            refresh_root: secrets.refresh_root,
            sending_chain,
            receiving_chain,
            skipped_keys: SkippedKeyStore::default(),
            replay: ReplayWindow::default(),
            active_refresh_id: None,
        }
    }

    #[must_use]
    pub const fn role(&self) -> SessionRole {
        self.role
    }

    #[must_use]
    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    #[must_use]
    pub const fn transcript_hash(&self) -> &[u8; 64] {
        &self.transcript_hash
    }

    #[must_use]
    pub const fn local_identity_fingerprint(&self) -> &[u8; 32] {
        &self.local_identity_fingerprint
    }

    #[must_use]
    pub const fn remote_identity_fingerprint(&self) -> &[u8; 32] {
        &self.remote_identity_fingerprint
    }

    #[must_use]
    pub const fn next_send_index(&self) -> u64 {
        self.sending_chain.next_index()
    }

    #[must_use]
    pub const fn next_receive_index(&self) -> u64 {
        self.receiving_chain.next_index()
    }

    #[must_use]
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    /// Returns the bounded set of route tags that can currently authenticate
    /// an inbound envelope for this session. This supports constant-memory
    /// dispatch without attempting ratchet work against every active session.
    #[doc(hidden)]
    pub fn candidate_receive_route_tags(&self) -> crate::SessionResult<Vec<[u8; 16]>> {
        let direction = match self.role {
            SessionRole::Initiator => Direction::ResponderToInitiator,
            SessionRole::Responder => Direction::InitiatorToResponder,
        };
        let mut tags = Vec::with_capacity(MAX_SKIP + 1);
        self.skipped_keys
            .append_receive_route_tags(&self.session_id, direction, &mut tags);

        let future_count = MAX_SKIP
            .checked_sub(self.skipped_keys.len())
            .ok_or(crate::SessionError::InvalidState)?
            .saturating_add(1);
        let mut cursor = self.receiving_chain.next_index();
        let mut provisional_chain: Option<SecretBytes<32>> = None;
        for _ in 0..future_count {
            if cursor == u64::MAX {
                break;
            }
            let chain_key = provisional_chain
                .as_ref()
                .unwrap_or_else(|| self.receiving_chain.key());
            let step = derive_step(chain_key, &self.session_id, cursor)?;
            tags.push(step.route_tag);
            provisional_chain = Some(step.next_chain_key);
            cursor = cursor
                .checked_add(1)
                .ok_or(crate::SessionError::CounterExhausted)?;
        }
        Ok(tags)
    }
}
