use crate::{
    refresh::{derive_refresh_candidate, RefreshCandidate, RefreshRole, VerifiedRefresh},
    SessionError, SessionResult,
};

use super::{RefreshIdDecision, SessionPhase, SessionState};

impl SessionState {
    pub fn begin_refresh(&mut self, refresh_id: [u8; 32]) -> SessionResult<RefreshIdDecision> {
        match (self.phase, self.active_refresh_id) {
            (SessionPhase::Established, None) => {
                self.phase = SessionPhase::Refreshing;
                self.active_refresh_id = Some(refresh_id);
                Ok(RefreshIdDecision::Accepted)
            }
            (SessionPhase::Refreshing, Some(active)) if refresh_id < active => {
                self.active_refresh_id = Some(refresh_id);
                Ok(RefreshIdDecision::ReplacedLocal)
            }
            (SessionPhase::Refreshing, Some(active)) if refresh_id == active => {
                Ok(RefreshIdDecision::Accepted)
            }
            (SessionPhase::Refreshing, Some(_)) => Err(SessionError::RefreshConflict),
            _ => Err(SessionError::InvalidState),
        }
    }

    pub fn abort_refresh(&mut self) -> SessionResult<()> {
        if self.phase != SessionPhase::Refreshing {
            return Err(SessionError::InvalidState);
        }
        self.active_refresh_id = None;
        self.phase = SessionPhase::Established;
        Ok(())
    }

    pub fn derive_refresh_candidate(
        &self,
        local_role: RefreshRole,
        refresh_mix: &[u8; 32],
        pretranscript: [u8; 64],
        transcript_hash: [u8; 64],
    ) -> SessionResult<RefreshCandidate> {
        if self.phase != SessionPhase::Refreshing {
            return Err(SessionError::InvalidState);
        }
        derive_refresh_candidate(
            local_role,
            self.session_id,
            &self.refresh_root,
            refresh_mix,
            pretranscript,
            transcript_hash,
        )
    }

    pub fn install_refresh(&mut self, verified: VerifiedRefresh) -> SessionResult<()> {
        if self.phase != SessionPhase::Refreshing {
            return Err(SessionError::InvalidState);
        }
        let (old_id, new_id, transcript, local_role, chain_i2r, chain_r2i, refresh_root) =
            verified.into_parts();
        if old_id != self.session_id {
            return Err(SessionError::InvalidState);
        }
        let (sending_chain, receiving_chain) = match local_role {
            RefreshRole::Initiator => (chain_i2r, chain_r2i),
            RefreshRole::Responder => (chain_r2i, chain_i2r),
        };
        self.session_id = new_id;
        self.transcript_hash = transcript;
        self.refresh_root = refresh_root;
        self.sending_chain = sending_chain;
        self.receiving_chain = receiving_chain;
        self.skipped_keys.clear();
        self.replay.clear();
        self.active_refresh_id = None;
        self.phase = SessionPhase::Established;
        Ok(())
    }
}
