use super::rollback::generation_bound_content;
use crate::{
    codec::unpack_lobby_payload,
    packet_fragments::{is_packet_fragment_for_kind, FragmentKind},
    ContactId, Hydra, HydraEnvelope, HydraMsgError, HydraResult, HydraSessionStatus,
};
use hydra_core::types::ContentKind;
use hydra_envelope::ProtectedRecord;
use hydra_session::{SessionError, SessionResult};

fn validate_direct_record(record: &ProtectedRecord) -> SessionResult<()> {
    if record.content_kind == ContentKind::Close {
        return Ok(());
    }
    let content =
        generation_bound_content(&record.content).ok_or(SessionError::AuthenticationFailed)?;
    if record.content_kind == ContentKind::Data
        && !is_packet_fragment_for_kind(FragmentKind::Lobby, content)
        && unpack_lobby_payload(content).is_err()
    {
        Ok(())
    } else {
        Err(SessionError::AuthenticationFailed)
    }
}

impl Hydra {
    pub fn session_status(&self, contact_id: ContactId) -> HydraResult<HydraSessionStatus> {
        if let Some(session) = self.sessions.get(&contact_id) {
            return Ok(if session.closed {
                HydraSessionStatus::Closed
            } else {
                HydraSessionStatus::Active
            });
        }
        let pending =
            self.pending_offers
                .values()
                .any(|offer| offer.contact_id == contact_id)
                || self.accepted_inits.values().any(|accepted| {
                    accepted.contact_id == contact_id && accepted.candidate.is_some()
                });
        Ok(if pending {
            HydraSessionStatus::Pending
        } else {
            HydraSessionStatus::Missing
        })
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
        let bound_payload = self.wrap_outbound_generation(payload)?;
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        let outbound = session.state.send_data_with_envelope_bounds(
            &bound_payload,
            min_envelope_size,
            max_envelope_size,
        )?;
        Ok(HydraEnvelope(outbound.envelope))
    }

    pub(crate) fn seal_compact_payload_for_contact(
        &mut self,
        contact_id: ContactId,
        payload: &[u8],
    ) -> HydraResult<HydraEnvelope> {
        let contact = self.require_contact(contact_id)?;
        if contact.blocked {
            return Err(HydraMsgError::InvalidInput("contact is blocked"));
        }
        if payload.len()
            > hydra_session::MAX_COMPACT_CONTENT_SIZE
                .saturating_sub(crate::STATE_GENERATION_BINDING_OVERHEAD)
        {
            return Err(HydraMsgError::InvalidInput(
                "payload exceeds compact carrier capacity",
            ));
        }
        let bound_payload = self.wrap_outbound_generation(payload)?;
        let session = self
            .sessions
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if session.closed {
            return Err(HydraMsgError::SessionNotFound);
        }
        let outbound = session.state.send_compact_data(&bound_payload)?;
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
                session
                    .state
                    .receive_validated(envelope, validate_direct_record)
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
                    let content = self.accept_inbound_generation(contact_id, message.content)?;
                    return Ok((contact_id, content));
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

    pub(crate) fn open_compact_payload_from_contact(
        &mut self,
        envelope: &[u8],
    ) -> HydraResult<(ContactId, Vec<u8>)> {
        let candidates = self.receive_compact_route_candidates(envelope)?;
        for contact_id in candidates {
            let result = {
                let Some(session) = self.sessions.get_mut(&contact_id) else {
                    continue;
                };
                if session.closed {
                    continue;
                }
                session.state.receive_compact(envelope)
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
                    let content = self.accept_inbound_generation(contact_id, message.content)?;
                    return Ok((contact_id, content));
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
                    let content = generation_bound_content(&record.content)
                        .ok_or(SessionError::AuthenticationFailed)?;
                    if record.content_kind == ContentKind::Data
                        && (is_packet_fragment_for_kind(FragmentKind::Lobby, content)
                            || unpack_lobby_payload(content).is_ok())
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
                    let content = self.accept_inbound_generation(contact_id, message.content)?;
                    return Ok((contact_id, content));
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
