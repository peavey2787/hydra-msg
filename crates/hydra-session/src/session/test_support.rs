#[cfg(test)]
use hydra_core::types::ContentKind;
use hydra_core::types::EnvelopeClass;
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
#[cfg(test)]
use hydra_envelope::{encode_protected_record, ProtectedRecord};

use crate::{ratchet::derive_step, SessionError, SessionResult};

use super::{OutboundMessage, SessionState};

impl SessionState {
    pub fn set_test_send_index(&mut self, index: u64) {
        let key = SecretBytes::from_array(*self.sending_chain.key().expose_secret());
        self.sending_chain.install(key, index);
    }

    #[cfg(test)]
    pub(crate) fn send_invalid_binding_for_test(&mut self) -> SessionResult<OutboundMessage> {
        self.seal_record(
            EnvelopeClass::Lite,
            ProtectedRecord {
                content_kind: ContentKind::Data,
                session_or_group_id: self.session_id,
                sender_id: [1; 32],
                epoch: 0,
                state_version: 0,
                message_index: self.sending_chain.next_index(),
                content: b"invalid binding".to_vec(),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn seal_record_for_test(
        &mut self,
        class: EnvelopeClass,
        record: ProtectedRecord,
    ) -> SessionResult<OutboundMessage> {
        let index = self.sending_chain.next_index();
        if index == u64::MAX {
            return Err(SessionError::CounterExhausted);
        }
        let step = derive_step(self.sending_chain.key(), &self.session_id, index)?;
        let plaintext =
            encode_protected_record(class, &record).map_err(|_| SessionError::InvalidPayload)?;
        self.seal_plaintext(class, index, step, &plaintext)
    }

    pub fn seal_test_plaintext(
        &mut self,
        class: EnvelopeClass,
        plaintext: &[u8],
    ) -> SessionResult<OutboundMessage> {
        if plaintext.len() != class.protected_record_size() {
            return Err(SessionError::InvalidPayload);
        }
        let index = self.sending_chain.next_index();
        if index == u64::MAX {
            return Err(SessionError::CounterExhausted);
        }
        let step = derive_step(self.sending_chain.key(), &self.session_id, index)?;
        self.seal_plaintext(class, index, step, plaintext)
    }

    #[must_use]
    pub fn test_state_hash(&self) -> [u8; 32] {
        let mut state = Vec::new();
        state.extend_from_slice(b"HYDRA-MSG/test/session-state");
        state.push(self.role as u8);
        state.push(self.phase as u8);
        state.extend_from_slice(&self.session_id);
        state.extend_from_slice(&self.transcript_hash);
        state.extend_from_slice(&self.local_identity_fingerprint);
        state.extend_from_slice(&self.remote_identity_fingerprint);
        state.extend_from_slice(self.refresh_root.expose_secret());
        state.extend_from_slice(self.sending_chain.key().expose_secret());
        state.extend_from_slice(&self.sending_chain.next_index().to_be_bytes());
        state.extend_from_slice(self.receiving_chain.key().expose_secret());
        state.extend_from_slice(&self.receiving_chain.next_index().to_be_bytes());
        self.skipped_keys.append_test_commitment(&mut state);
        self.replay.append_test_commitment(&mut state);
        match self.active_refresh_id {
            Some(id) => {
                state.push(1);
                state.extend_from_slice(&id);
            }
            None => state.extend_from_slice(&[0; 33]),
        }
        RustCryptoBackend::sha3_256(&state)
    }
}
