use hydra_crypto::SecretBytes;
use hydra_session::{
    derive_initial_secrets, OutboundMessage, ReceivedMessage, SessionRole, SessionState,
    SessionStateSnapshot,
};

use crate::{random::random_array, AppError, AppIdentity, AppResult, PublicIdentity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSessionRole {
    Initiator,
    Responder,
}

impl From<AppSessionRole> for SessionRole {
    fn from(value: AppSessionRole) -> Self {
        match value {
            AppSessionRole::Initiator => Self::Initiator,
            AppSessionRole::Responder => Self::Responder,
        }
    }
}

/// Opaque output from a completed authenticated handshake.
///
/// The app facade consumes this material to start a ratcheted 1:1 session. The
/// raw secret is not exposed again by this type.
pub struct SessionHandshakeExport {
    handshake_secret: SecretBytes<32>,
    transcript_hash: [u8; 64],
}

impl SessionHandshakeExport {
    #[must_use]
    pub fn from_handshake_layer(
        handshake_secret: SecretBytes<32>,
        transcript_hash: [u8; 64],
    ) -> Self {
        Self {
            handshake_secret,
            transcript_hash,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn from_test_bytes(handshake_secret: [u8; 32], transcript_hash: [u8; 64]) -> Self {
        Self::from_handshake_layer(SecretBytes::from_array(handshake_secret), transcript_hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectRekeyPolicy {
    pub every_messages: u64,
}

impl DirectRekeyPolicy {
    pub const fn new(every_messages: u64) -> Self {
        Self { every_messages }
    }

    #[must_use]
    pub const fn should_rekey(self, next_send_index: u64) -> bool {
        self.every_messages != 0 && next_send_index >= self.every_messages
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppDirectRekeyNotice {
    refresh_id: [u8; 32],
    next_send_index: u64,
    threshold: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AppSessionPolicySend {
    Sent(AppSessionWireMessage),
    RekeyStarted(AppDirectRekeyNotice),
}

#[derive(Debug, PartialEq, Eq)]
pub struct AppSessionWireMessage {
    index: u64,
    envelope: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AppSessionMessage {
    index: u64,
    content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AppSessionSnapshot {
    pub state: SessionStateSnapshot,
    pub local_identity: PublicIdentity,
    pub peer_identity: PublicIdentity,
}

pub struct AppSession {
    state: SessionState,
    local_identity: PublicIdentity,
    peer_identity: PublicIdentity,
}

impl AppSession {
    pub fn start(
        role: AppSessionRole,
        local_identity: &AppIdentity,
        peer_identity: PublicIdentity,
        export: SessionHandshakeExport,
    ) -> AppResult<Self> {
        let public_local = local_identity.public_identity();
        if public_local.fingerprint() == peer_identity.fingerprint() {
            return Err(AppError::InvalidInput(
                "peer identity must differ from local identity",
            ));
        }
        let secrets = derive_initial_secrets(&export.handshake_secret, &export.transcript_hash)?;
        let state = SessionState::established(
            role.into(),
            export.transcript_hash,
            public_local.fingerprint().0,
            peer_identity.fingerprint().0,
            secrets,
        );
        Ok(Self {
            state,
            local_identity: public_local,
            peer_identity,
        })
    }

    pub fn send(&mut self, content: &[u8]) -> AppResult<AppSessionWireMessage> {
        let OutboundMessage { index, envelope } = self.state.send_data(content)?;
        Ok(AppSessionWireMessage { index, envelope })
    }

    pub fn send_with_rekey_policy(
        &mut self,
        content: &[u8],
        policy: DirectRekeyPolicy,
    ) -> AppResult<AppSessionPolicySend> {
        let next_send_index = self.state.next_send_index();
        if policy.should_rekey(next_send_index) {
            let refresh_id = random_array::<32>()?;
            self.state.begin_refresh(refresh_id)?;
            return Ok(AppSessionPolicySend::RekeyStarted(AppDirectRekeyNotice {
                refresh_id,
                next_send_index,
                threshold: policy.every_messages,
            }));
        }
        self.send(content).map(AppSessionPolicySend::Sent)
    }

    pub fn receive(&mut self, envelope: &[u8]) -> AppResult<AppSessionMessage> {
        let ReceivedMessage { index, content, .. } = self.state.receive(envelope)?;
        Ok(AppSessionMessage { index, content })
    }

    pub fn close(&mut self, reason_code: u16) -> AppResult<AppSessionWireMessage> {
        let OutboundMessage { index, envelope } = self.state.send_close(reason_code)?;
        Ok(AppSessionWireMessage { index, envelope })
    }

    #[must_use]
    pub fn export_snapshot(&self) -> AppSessionSnapshot {
        AppSessionSnapshot {
            state: self.state.export_snapshot(),
            local_identity: self.local_identity.clone(),
            peer_identity: self.peer_identity.clone(),
        }
    }

    pub fn from_snapshot(snapshot: AppSessionSnapshot) -> AppResult<Self> {
        if snapshot.state.local_identity_fingerprint != snapshot.local_identity.fingerprint().0 {
            return Err(AppError::InvalidInput(
                "session snapshot local identity mismatch",
            ));
        }
        if snapshot.state.remote_identity_fingerprint != snapshot.peer_identity.fingerprint().0 {
            return Err(AppError::InvalidInput(
                "session snapshot peer identity mismatch",
            ));
        }
        Ok(Self {
            state: SessionState::from_snapshot(snapshot.state),
            local_identity: snapshot.local_identity,
            peer_identity: snapshot.peer_identity,
        })
    }

    #[must_use]
    pub const fn local_identity(&self) -> &PublicIdentity {
        &self.local_identity
    }

    #[must_use]
    pub const fn peer_identity(&self) -> &PublicIdentity {
        &self.peer_identity
    }
}

impl AppDirectRekeyNotice {
    #[must_use]
    pub const fn refresh_id(&self) -> [u8; 32] {
        self.refresh_id
    }

    #[must_use]
    pub const fn next_send_index(&self) -> u64 {
        self.next_send_index
    }

    #[must_use]
    pub const fn threshold(&self) -> u64 {
        self.threshold
    }
}

impl AppSessionPolicySend {
    #[must_use]
    pub fn rekey_started(&self) -> bool {
        matches!(self, Self::RekeyStarted(_))
    }
}

impl AppSessionWireMessage {
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    #[must_use]
    pub fn as_envelope(&self) -> &[u8] {
        &self.envelope
    }

    #[must_use]
    pub fn into_envelope(self) -> Vec<u8> {
        self.envelope
    }
}

impl AppSessionMessage {
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    #[must_use]
    pub fn into_content(self) -> Vec<u8> {
        self.content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (AppSession, AppSession) {
        let alice = AppIdentity::generate().unwrap();
        let bob = AppIdentity::generate().unwrap();
        let transcript = [0x33; 64];
        let secret = [0x44; 32];
        let alice_session = AppSession::start(
            AppSessionRole::Initiator,
            &alice,
            bob.public_identity(),
            SessionHandshakeExport::from_test_bytes(secret, transcript),
        )
        .unwrap();
        let bob_session = AppSession::start(
            AppSessionRole::Responder,
            &bob,
            alice.public_identity(),
            SessionHandshakeExport::from_test_bytes(secret, transcript),
        )
        .unwrap();
        (alice_session, bob_session)
    }

    #[test]
    fn app_session_sends_receives_and_rejects_replay() {
        let (mut alice, mut bob) = pair();
        let outbound = alice.send(b"hello from app").unwrap();
        let received = bob.receive(outbound.as_envelope()).unwrap();
        assert_eq!(received.content(), b"hello from app");
        assert_eq!(
            bob.receive(outbound.as_envelope()).unwrap_err().class(),
            crate::AppErrorClass::Replay
        );
    }

    #[test]
    fn direct_policy_threshold_starts_refresh_and_blocks_data_send() {
        let (mut alice, _bob) = pair();
        let sent = alice
            .send_with_rekey_policy(b"first", DirectRekeyPolicy::new(1))
            .unwrap();
        assert!(matches!(sent, AppSessionPolicySend::Sent(_)));
        let triggered = alice
            .send_with_rekey_policy(b"second", DirectRekeyPolicy::new(1))
            .unwrap();
        assert!(triggered.rekey_started());
        assert_eq!(
            alice.send(b"data while refreshing").unwrap_err().class(),
            crate::AppErrorClass::InvalidState
        );
    }
}
