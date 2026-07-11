use hydra_crypto::SecretBytes;

use crate::{ratchet::DirectionChain, skipped_keys::SkippedKeyStore, SessionResult};

use super::{SessionState, SessionStateSnapshot};

impl SessionState {
    #[must_use]
    pub fn export_snapshot(&self) -> SessionStateSnapshot {
        SessionStateSnapshot {
            role: self.role,
            phase: self.phase,
            session_id: self.session_id,
            transcript_hash: self.transcript_hash,
            local_identity_fingerprint: self.local_identity_fingerprint,
            remote_identity_fingerprint: self.remote_identity_fingerprint,
            refresh_root: *self.refresh_root.expose_secret(),
            sending_chain: self.sending_chain.export_snapshot(),
            receiving_chain: self.receiving_chain.export_snapshot(),
            skipped_keys: self.skipped_keys.export_snapshot(),
            replay: self.replay.export_snapshot(),
            active_refresh_id: self.active_refresh_id,
        }
    }

    pub fn from_snapshot(snapshot: SessionStateSnapshot) -> SessionResult<Self> {
        Ok(Self {
            role: snapshot.role,
            phase: snapshot.phase,
            session_id: snapshot.session_id,
            transcript_hash: snapshot.transcript_hash,
            local_identity_fingerprint: snapshot.local_identity_fingerprint,
            remote_identity_fingerprint: snapshot.remote_identity_fingerprint,
            refresh_root: SecretBytes::from_array(snapshot.refresh_root),
            sending_chain: DirectionChain::from_snapshot(snapshot.sending_chain),
            receiving_chain: DirectionChain::from_snapshot(snapshot.receiving_chain),
            skipped_keys: SkippedKeyStore::from_snapshot(snapshot.skipped_keys)?,
            replay: hydra_core::protocol::replay::ReplayWindow::from_snapshot(snapshot.replay),
            active_refresh_id: snapshot.active_refresh_id,
        })
    }
}
