use super::{
    helpers::{expire_handshakes, retire_competing_handshakes},
    HandshakeFinish, HandshakePurpose,
};
use crate::{
    codec::{
        decode_handshake_answer, encode_handshake_finish, identity_fingerprint,
        verify_answer_and_derive, verify_handshake_finish,
    },
    limits::{reject_encoded_size, MAX_HANDSHAKE_FINISH_BYTES},
    ContactId, Hydra, HydraMsgError, HydraResult,
};
use hydra_core::types::{EnvelopeClass, OuterMode};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};
use hydra_envelope::decode_outer_header;
use hydra_session::{derive_initial_secrets, SessionRole, SessionState};

impl Hydra {
    pub(crate) fn finish_handshake_for(
        &mut self,
        answer: impl AsRef<[u8]>,
        expected_purpose: HandshakePurpose,
    ) -> HydraResult<HandshakeFinish> {
        let parsed_answer = decode_handshake_answer(answer.as_ref())?;
        expire_handshakes(self);
        let active = self.active_unlocked_record()?.clone();
        let (contact_id, finish, state) = {
            let pending = self
                .pending_offers
                .get(&parsed_answer.init_hash)
                .ok_or(HydraMsgError::InvalidInput("unknown handshake answer"))?;
            if pending.purpose != expected_purpose {
                return Err(HydraMsgError::InvalidInput(
                    "handshake answer has the wrong local purpose",
                ));
            }
            if pending.local_identity_id != active.id {
                return Err(HydraMsgError::InvalidInput(
                    "active identity changed during handshake",
                ));
            }
            if pending.contact_id != ContactId(parsed_answer.peer_id.0) {
                return Err(HydraMsgError::InvalidInput(
                    "handshake answer does not match pending contact",
                ));
            }
            let contact = self.require_contact(pending.contact_id)?;
            if parsed_answer.responder_fingerprint != identity_fingerprint(&contact.public_key) {
                return Err(HydraMsgError::InvalidInput(
                    "RESP responder fingerprint does not match contact",
                ));
            }
            let x25519_shared = RustCryptoBackend::x25519_diffie_hellman(
                &pending.x25519_secret,
                &parsed_answer.x25519_public,
            )?;
            let kem_shared = RustCryptoBackend::mlkem768_decapsulate(
                &pending.kem_decapsulation_key,
                &parsed_answer.kem_ciphertext,
            )?;
            let material = verify_answer_and_derive(
                &parsed_answer,
                &pending.offer,
                &x25519_shared,
                &kem_shared,
            )?;
            let finish = encode_handshake_finish(&material)?;
            let secrets =
                derive_initial_secrets(&material.handshake_secret, &material.transcript_hash)?;
            let state = SessionState::established(
                SessionRole::Initiator,
                material.transcript_hash,
                active.id.0,
                parsed_answer.peer_id.0,
                secrets,
            );
            (pending.contact_id, finish, state)
        };
        self.install_session(contact_id, state)?;
        retire_competing_handshakes(self, contact_id, None);
        Ok(HandshakeFinish(finish))
    }

    pub(crate) fn accept_handshake_finish_for(
        &mut self,
        finish: impl AsRef<[u8]>,
        expected_purpose: HandshakePurpose,
    ) -> HydraResult<()> {
        expire_handshakes(self);
        let finish = finish.as_ref();
        reject_encoded_size(
            finish.len(),
            MAX_HANDSHAKE_FINISH_BYTES,
            "handshake FINISH size",
        )?;
        if finish.len() != EnvelopeClass::Lite.envelope_size() {
            return Err(HydraMsgError::InvalidEncoding("FINISH envelope size"));
        }
        let header = decode_outer_header(finish)
            .map_err(|_| HydraMsgError::InvalidEncoding("FINISH outer header"))?;
        // `finish.len()` is already fixed to Lite and `decode_outer_header()`
        // validates that the encoded class agrees with that exact length.
        if header.mode != OuterMode::Protected {
            return Err(HydraMsgError::InvalidEncoding("FINISH outer header"));
        }
        if header.counter != 0 {
            return Err(HydraMsgError::InvalidEncoding("FINISH outer header"));
        }
        let finish_hash = RustCryptoBackend::sha3_256(finish);
        let key = self
            .accepted_inits
            .iter()
            .find_map(|(key, entry)| (entry.finish_route_tag == header.route_tag).then_some(*key))
            .ok_or(HydraMsgError::InvalidInput("unknown handshake FINISH"))?;
        let active = self.active_unlocked_record()?.clone();
        let (contact_id, state) = {
            let entry = self
                .accepted_inits
                .get(&key)
                .ok_or(HydraMsgError::InvalidInput("unknown handshake FINISH"))?;
            if let Some(accepted) = entry.accepted_finish_hash {
                return if accepted == finish_hash {
                    Ok(())
                } else {
                    Err(HydraMsgError::InvalidInput("conflicting handshake FINISH"))
                };
            }
            if entry.local_identity_id != active.id {
                return Err(HydraMsgError::InvalidInput(
                    "active identity changed during handshake",
                ));
            }
            let candidate = entry.candidate.as_ref().ok_or(HydraMsgError::InvalidInput(
                "handshake FINISH has no provisional state",
            ))?;
            if entry.purpose != expected_purpose {
                return Err(HydraMsgError::InvalidInput(
                    "handshake FINISH has the wrong local purpose",
                ));
            }
            verify_handshake_finish(finish, &candidate.material)?;
            let secrets = derive_initial_secrets(
                &candidate.material.handshake_secret,
                &candidate.material.transcript_hash,
            )?;
            let state = SessionState::established(
                SessionRole::Responder,
                candidate.material.transcript_hash,
                active.id.0,
                entry.contact_id.0,
                secrets,
            );
            (entry.contact_id, state)
        };
        self.install_session(contact_id, state)?;
        retire_competing_handshakes(self, contact_id, Some(key));
        if let Some(entry) = self.accepted_inits.get_mut(&key) {
            entry.candidate = None;
            entry.accepted_finish_hash = Some(finish_hash);
        }
        self.persist()?;
        Ok(())
    }
}
