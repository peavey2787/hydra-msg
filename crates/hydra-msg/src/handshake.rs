use crate::{codec::*, ContactId, Hydra, HydraContact, HydraMsgError, HydraResult, LobbyId};
use hydra_core::FULL_MAX_CONTENT_SIZE;
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

#[derive(Clone)]
pub(crate) struct PendingOffer {
    pub(crate) contact_id: ContactId,
    pub(crate) nonce: [u8; 32],
}

impl Hydra {
    pub fn init_handshake(&mut self, contact_id: ContactId) -> HydraResult<HandshakeOffer> {
        self.require_contact(contact_id)?;
        let record = self.active_unlocked_record()?;
        let nonce = random_array::<32>()?;
        let offer = encode_handshake_offer(record.id, &record.public_key, nonce);
        self.pending_offers
            .insert(nonce, PendingOffer { contact_id, nonce });
        Ok(HandshakeOffer(offer))
    }

    pub fn reply_handshake(&mut self, offer: impl AsRef<[u8]>) -> HydraResult<HandshakeAnswer> {
        let parsed = decode_handshake_offer(offer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        let contact_id = ContactId(parsed.peer_id.0);
        self.contacts
            .entry(contact_id)
            .or_insert_with(|| HydraContact {
                id: contact_id,
                label: format!("contact-{}", contact_id.hex()),
                public_key: parsed.public_key,
                verified: false,
                blocked: false,
            });
        let (secret, transcript_hash) =
            derive_facade_handshake_material(parsed.nonce, parsed.peer_id, active.id);
        let secrets = derive_initial_secrets(&secret, &transcript_hash)?;
        let state = SessionState::established(
            SessionRole::Responder,
            transcript_hash,
            active.id.0,
            parsed.peer_id.0,
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
        Ok(HandshakeAnswer(encode_handshake_answer(
            active.id,
            &active.public_key,
            parsed.nonce,
        )))
    }

    pub fn finish_handshake(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<()> {
        let parsed = decode_handshake_answer(answer.as_ref())?;
        let active = self.active_unlocked_record()?.clone();
        let pending = self
            .pending_offers
            .remove(&parsed.nonce)
            .ok_or(HydraMsgError::InvalidInput("unknown handshake answer"))?;
        if pending.contact_id != ContactId(parsed.peer_id.0) {
            return Err(HydraMsgError::InvalidInput(
                "handshake answer does not match pending contact",
            ));
        }
        let _ = pending.nonce;
        let (secret, transcript_hash) =
            derive_facade_handshake_material(parsed.nonce, active.id, parsed.peer_id);
        let secrets = derive_initial_secrets(&secret, &transcript_hash)?;
        let state = SessionState::established(
            SessionRole::Initiator,
            transcript_hash,
            active.id.0,
            parsed.peer_id.0,
            secrets,
        );
        self.sessions.insert(
            pending.contact_id,
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
