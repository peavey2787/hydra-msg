mod routing;
mod types;

pub use types::{HandshakeAnswer, HandshakeOffer, HydraEnvelope, HydraSessionStatus};
pub(crate) use types::{PendingOffer, SessionRecord};

use crate::{
    codec::*,
    limits::{
        reject_collection_growth, MAX_CONTACTS, MAX_PENDING_HANDSHAKES,
        MAX_PENDING_HANDSHAKE_AGE_SECS,
    },
    packet_fragments::{is_packet_fragment_for_kind, FragmentKind},
    ContactId, Hydra, HydraContact, HydraMsgError, HydraResult,
};
use hydra_core::types::ContentKind;
use hydra_crypto::{CryptoBackend, MlDsaKeyPair, MlKemEncapsulationKey, RustCryptoBackend};
use hydra_session::{derive_initial_secrets, SessionError, SessionRole, SessionState};
use std::time::Duration;

fn identity_signing_key(
    record: &crate::identity::IdentityRecord,
) -> HydraResult<hydra_crypto::MlDsaSigningKey> {
    let seed = record
        .seed
        .ok_or(HydraMsgError::InvalidInput("active identity is locked"))?;
    Ok(MlDsaKeyPair::from_seed(seed)?.signing_key)
}

impl Hydra {
    pub fn init_handshake(&mut self, contact_id: ContactId) -> HydraResult<HandshakeOffer> {
        self.require_contact(contact_id)?;
        self.expire_pending_handshakes();
        reject_collection_growth(
            self.pending_offers.len(),
            1,
            MAX_PENDING_HANDSHAKES,
            "pending handshake limit",
        )?;
        let record = self.active_unlocked_record()?.clone();
        let signing_key = identity_signing_key(&record)?;
        let nonce = random_array::<32>()?;
        let x25519_secret = RustCryptoBackend::x25519_generate()?;
        let x25519_public = x25519_secret.public_key();
        let kem_keypair = RustCryptoBackend::mlkem768_generate()?;
        let kem_public_key = kem_keypair.encapsulation_key.to_bytes();
        let offer = encode_handshake_offer(
            record.id,
            &record.public_key,
            nonce,
            x25519_public,
            &kem_public_key,
            &signing_key,
        )?;
        let parsed_offer = decode_handshake_offer(&offer)?;
        self.pending_offers.insert(
            nonce,
            PendingOffer {
                contact_id,
                offer: parsed_offer,
                x25519_secret,
                kem_decapsulation_key: kem_keypair.decapsulation_key,
                created_at: crate::time::HydraInstant::now(),
            },
        );
        Ok(HandshakeOffer(offer))
    }

    pub fn reply_handshake(&mut self, offer: impl AsRef<[u8]>) -> HydraResult<HandshakeAnswer> {
        let parsed_offer = decode_handshake_offer(offer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        let contact_id = ContactId(parsed_offer.peer_id.0);
        if self
            .contacts
            .get(&contact_id)
            .is_some_and(|contact| contact.blocked)
        {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        let new_contact = if self.contacts.contains_key(&contact_id) {
            None
        } else {
            reject_collection_growth(self.contacts.len(), 1, MAX_CONTACTS, "contact limit")?;
            Some(HydraContact {
                id: contact_id,
                label: format!("contact-{}", contact_id.hex()),
                public_key: parsed_offer.public_key,
                verified: false,
                blocked: false,
            })
        };

        let signing_key = identity_signing_key(&active)?;
        let x25519_secret = RustCryptoBackend::x25519_generate()?;
        let x25519_public = x25519_secret.public_key();
        let x25519_shared =
            RustCryptoBackend::x25519_diffie_hellman(&x25519_secret, &parsed_offer.x25519_public)?;
        let kem_public_key = MlKemEncapsulationKey::from_bytes(&parsed_offer.kem_public_key)?;
        let (kem_ciphertext, kem_shared) =
            RustCryptoBackend::mlkem768_encapsulate(&kem_public_key)?;
        let nonce = random_array::<32>()?;
        let answer = encode_handshake_answer(HandshakeAnswerParts {
            id: active.id,
            public_key: &active.public_key,
            offer_nonce: parsed_offer.nonce,
            nonce,
            x25519_public,
            kem_ciphertext: &kem_ciphertext,
            offer: &parsed_offer,
            signing_key: &signing_key,
            x25519_secret: &x25519_shared,
            kem_secret: &kem_shared,
        })?;
        let parsed_answer = decode_handshake_answer(&answer)?;
        verify_answer_signature(&parsed_answer, &parsed_offer)?;
        let (secret, transcript_hash) =
            verify_answer_confirmation(&parsed_answer, &parsed_offer, &x25519_shared, &kem_shared)?;
        let secrets = derive_initial_secrets(&secret, &transcript_hash)?;
        let state = SessionState::established(
            SessionRole::Responder,
            transcript_hash,
            active.id.0,
            parsed_offer.peer_id.0,
            secrets,
        );
        if let Some(contact) = new_contact {
            self.contacts.insert(contact_id, contact);
        }
        self.install_session(contact_id, state)?;
        self.persist()?;
        Ok(HandshakeAnswer(answer))
    }

    pub fn finish_handshake(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<()> {
        let parsed_answer = decode_handshake_answer(answer.as_ref())?;
        self.expire_pending_handshakes();
        let active = self.active_unlocked_record()?.clone();
        let pending = self
            .pending_offers
            .get(&parsed_answer.offer_nonce)
            .ok_or(HydraMsgError::InvalidInput("unknown handshake answer"))?;
        if pending.contact_id != ContactId(parsed_answer.peer_id.0) {
            return Err(HydraMsgError::InvalidInput(
                "handshake answer does not match pending contact",
            ));
        }
        verify_answer_signature(&parsed_answer, &pending.offer)?;
        let x25519_shared = RustCryptoBackend::x25519_diffie_hellman(
            &pending.x25519_secret,
            &parsed_answer.x25519_public,
        )?;
        let kem_shared = RustCryptoBackend::mlkem768_decapsulate(
            &pending.kem_decapsulation_key,
            &parsed_answer.kem_ciphertext,
        )?;
        let (secret, transcript_hash) = verify_answer_confirmation(
            &parsed_answer,
            &pending.offer,
            &x25519_shared,
            &kem_shared,
        )?;
        let contact_id = pending.contact_id;
        self.pending_offers.remove(&parsed_answer.offer_nonce);
        let secrets = derive_initial_secrets(&secret, &transcript_hash)?;
        let state = SessionState::established(
            SessionRole::Initiator,
            transcript_hash,
            active.id.0,
            parsed_answer.peer_id.0,
            secrets,
        );
        self.install_session(contact_id, state)?;
        Ok(())
    }

    fn expire_pending_handshakes(&mut self) {
        let max_age = Duration::from_secs(MAX_PENDING_HANDSHAKE_AGE_SECS);
        self.pending_offers
            .retain(|_, pending| pending.created_at.elapsed() <= max_age);
    }

    pub fn session_status(&self, contact_id: ContactId) -> HydraResult<HydraSessionStatus> {
        Ok(match self.sessions.get(&contact_id) {
            Some(session) if session.closed => HydraSessionStatus::Closed,
            Some(_) => HydraSessionStatus::Active,
            None => HydraSessionStatus::Missing,
        })
    }

    pub fn rekey_session(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        let refresh_id = random_array::<32>()?;
        session.state.begin_refresh(refresh_id)?;
        Ok(())
    }

    pub fn close_session(&mut self, contact_id: ContactId) -> HydraResult<()> {
        {
            let session = self
                .sessions
                .get_mut(&contact_id)
                .ok_or(HydraMsgError::SessionNotFound)?;
            session.closed = true;
        }
        self.remove_session_routes(contact_id);
        Ok(())
    }

    pub(crate) fn seal_payload_for_contact(
        &mut self,
        contact_id: ContactId,
        payload: &[u8],
    ) -> HydraResult<HydraEnvelope> {
        let contact = self.require_contact(contact_id)?;
        if contact.blocked {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        if payload.len() > self.max_payload_content_size()? {
            return Err(HydraMsgError::InvalidInput(
                "payload exceeds configured envelope capacity",
            ));
        }
        let (min_envelope_size, max_envelope_size) = self.envelope_size_bounds()?;
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        let outbound = session.state.send_data_with_envelope_bounds(
            payload,
            min_envelope_size,
            max_envelope_size,
        )?;
        Ok(HydraEnvelope(outbound.envelope))
    }

    pub(crate) fn open_payload_from_contact(
        &mut self,
        envelope: &[u8],
    ) -> HydraResult<(ContactId, Vec<u8>)> {
        self.validate_inbound_envelope_size(envelope.len())?;
        let candidates = self.receive_route_candidates(envelope)?;
        for contact_id in candidates {
            let result = {
                let Some(session) = self.sessions.get_mut(&contact_id) else {
                    continue;
                };
                if session.closed {
                    continue;
                }
                session.state.receive(envelope)
            };
            match result {
                Ok(message) => {
                    if message.content_kind == ContentKind::Close {
                        if let Some(session) = self.sessions.get_mut(&contact_id) {
                            session.closed = true;
                        }
                    }
                    self.refresh_session_routes(contact_id)?;
                    if self
                        .contacts
                        .get(&contact_id)
                        .is_some_and(|contact| contact.blocked)
                    {
                        return Err(HydraMsgError::InvalidInput("contact is blocked"));
                    }
                    return Ok((contact_id, message.content));
                }
                Err(SessionError::AuthenticationFailed) => {}
                Err(SessionError::ReplayDetected) => {
                    return Err(HydraMsgError::Session(
                        SessionError::ReplayDetected.to_string(),
                    ));
                }
                Err(error) => return Err(HydraMsgError::Session(error.to_string())),
            }
        }
        Err(HydraMsgError::SessionNotFound)
    }

    pub(crate) fn open_lobby_transport_payload_from_contact(
        &mut self,
        envelope: &[u8],
    ) -> HydraResult<(ContactId, Vec<u8>)> {
        self.validate_inbound_envelope_size(envelope.len())?;
        let candidates = self.receive_route_candidates(envelope)?;
        for contact_id in candidates {
            let result = {
                let Some(session) = self.sessions.get_mut(&contact_id) else {
                    continue;
                };
                if session.closed {
                    continue;
                }
                session.state.receive_validated(envelope, |record| {
                    if record.content_kind == ContentKind::Data
                        && (is_packet_fragment_for_kind(FragmentKind::Lobby, &record.content)
                            || unpack_lobby_payload(&record.content).is_ok())
                    {
                        Ok(())
                    } else {
                        Err(SessionError::AuthenticationFailed)
                    }
                })
            };
            match result {
                Ok(message) => {
                    self.refresh_session_routes(contact_id)?;
                    if self
                        .contacts
                        .get(&contact_id)
                        .is_some_and(|contact| contact.blocked)
                    {
                        return Err(HydraMsgError::InvalidInput("contact is blocked"));
                    }
                    return Ok((contact_id, message.content));
                }
                Err(SessionError::AuthenticationFailed) => {}
                Err(SessionError::ReplayDetected) => {
                    return Err(HydraMsgError::Session(
                        SessionError::ReplayDetected.to_string(),
                    ));
                }
                Err(error) => return Err(HydraMsgError::Session(error.to_string())),
            }
        }
        Err(HydraMsgError::SessionNotFound)
    }
}
