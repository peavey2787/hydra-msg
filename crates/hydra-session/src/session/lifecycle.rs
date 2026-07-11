use hydra_crypto::SecretBytes;

use crate::ratchet::DirectionChain;

use super::{SessionPhase, SessionState};

impl SessionState {
    pub fn full_wipe(&mut self) {
        self.refresh_root = SecretBytes::from_array([0; 32]);
        self.sending_chain = DirectionChain::new(SecretBytes::from_array([0; 32]));
        self.receiving_chain = DirectionChain::new(SecretBytes::from_array([0; 32]));
        self.skipped_keys.clear();
        self.replay.clear();
        self.active_refresh_id = None;
        self.session_id.fill(0);
        self.transcript_hash.fill(0);
        self.phase = SessionPhase::Closed;
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.full_wipe();
    }
}
