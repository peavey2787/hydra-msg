use crate::{codec::*, ContactId, Hydra, HydraContact, HydraMsgError, HydraResult, LobbyId};
use hydra_core::FULL_MAX_CONTENT_SIZE;
use hydra_crypto::{
    CryptoBackend, MlDsaKeyPair, MlKemDecapsulationKey, MlKemEncapsulationKey, RustCryptoBackend,
    X25519SecretKey,
};
use hydra_session::{derive_initial_secrets, SessionError, SessionRole, SessionState};

/// Opaque handshake offer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeOffer(pub(crate) Vec<u8>);

/// Opaque handshake answer bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeAnswer(pub(crate) Vec<u8>);

/// Opaque encrypted HYDRA envelope bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraEnvelope(pub(crate) Vec<u8>);

impl HandshakeOffer {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HandshakeOffer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HandshakeAnswer {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HandshakeAnswer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl HydraEnvelope {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HydraEnvelope {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Session status exposed to normal developers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HydraSessionStatus {
    Missing,
    Active,
    Closed,
}

pub(crate) struct SessionRecord {
    pub(crate) state: SessionState,
    pub(crate) closed: bool,
}

pub(crate) struct PendingOffer {
    pub(crate) contact_id: ContactId,
    pub(crate) offer: ParsedHandshakeOffer,
    pub(crate) x25519_secret: X25519SecretKey,
    pub(crate) kem_decapsulation_key: MlKemDecapsulationKey,
}

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
            },
        );
        Ok(HandshakeOffer(offer))
    }

    pub fn reply_handshake(&mut self, offer: impl AsRef<[u8]>) -> HydraResult<HandshakeAnswer> {
        let parsed_offer = decode_handshake_offer(offer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        let contact_id = ContactId(parsed_offer.peer_id.0);
        self.contacts
            .entry(contact_id)
            .or_insert_with(|| HydraContact {
                id: contact_id,
                label: format!("contact-{}", contact_id.hex()),
                public_key: parsed_offer.public_key,
                verified: false,
                blocked: false,
            });

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
        self.sessions.insert(
            contact_id,
            SessionRecord {
                state,
                closed: false,
            },
        );
        self.persist()?;
        Ok(HandshakeAnswer(answer))
    }

    pub fn finish_handshake(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<()> {
        let parsed_answer = decode_handshake_answer(answer.as_ref())?;
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
        self.sessions.insert(
            contact_id,
            SessionRecord {
                state,
                closed: false,
            },
        );
        Ok(())
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
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        session.closed = true;
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
        if payload.len() > FULL_MAX_CONTENT_SIZE {
            return Err(HydraMsgError::PayloadTooLarge);
        }
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        let outbound = session.state.send_data(payload)?;
        Ok(HydraEnvelope(outbound.envelope))
    }

    pub(crate) fn open_payload_from_contact(
        &mut self,
        envelope: &[u8],
    ) -> HydraResult<(ContactId, Vec<u8>)> {
        let matching_contact = self
            .sessions
            .iter_mut()
            .find_map(|(contact_id, session)| {
                if session.closed {
                    return None;
                }
                match session.state.receive(envelope) {
                    Ok(message) => Some(Ok((*contact_id, message.content))),
                    Err(SessionError::AuthenticationFailed) => None,
                    Err(SessionError::ReplayDetected) => Some(Err(HydraMsgError::Session(
                        SessionError::ReplayDetected.to_string(),
                    ))),
                    Err(error) => Some(Err(HydraMsgError::Session(error.to_string()))),
                }
            })
            .ok_or(HydraMsgError::SessionNotFound)??;
        if self
            .contacts
            .get(&matching_contact.0)
            .is_some_and(|contact| contact.blocked)
        {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        Ok(matching_contact)
    }

    pub(crate) fn open_lobby_payload_from_contact(
        &mut self,
        envelope: &[u8],
    ) -> HydraResult<(ContactId, LobbyId, Vec<u8>)> {
        for (contact_id, session) in &mut self.sessions {
            if session.closed {
                continue;
            }
            let snapshot = session.state.export_snapshot();
            match session.state.receive(envelope) {
                Ok(message) => {
                    if self
                        .contacts
                        .get(contact_id)
                        .is_some_and(|contact| contact.blocked)
                    {
                        session.state = SessionState::from_snapshot(snapshot);
                        return Err(HydraMsgError::InvalidInput("contact is blocked"));
                    }
                    match unpack_lobby_payload(&message.content) {
                        Ok((lobby_id, packed_message)) => {
                            return Ok((*contact_id, lobby_id, packed_message));
                        }
                        Err(error) => {
                            session.state = SessionState::from_snapshot(snapshot);
                            return Err(error);
                        }
                    }
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
