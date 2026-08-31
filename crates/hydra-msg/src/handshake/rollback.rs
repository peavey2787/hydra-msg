use crate::{ContactId, Hydra, HydraMsgError, HydraResult, STATE_GENERATION_BINDING_OVERHEAD};

const GENERATION_BINDING_MAGIC: &[u8] = b"HYDRA-MSG-GEN1";

pub(super) fn generation_bound_content(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < STATE_GENERATION_BINDING_OVERHEAD
        || &payload[..GENERATION_BINDING_MAGIC.len()] != GENERATION_BINDING_MAGIC
    {
        return None;
    }
    Some(&payload[STATE_GENERATION_BINDING_OVERHEAD..])
}

impl Hydra {
    pub(super) fn wrap_outbound_generation(&self, payload: &[u8]) -> HydraResult<Vec<u8>> {
        let generation = self.state_generation.saturating_add(1);
        let mut out = Vec::with_capacity(STATE_GENERATION_BINDING_OVERHEAD + payload.len());
        out.extend_from_slice(GENERATION_BINDING_MAGIC);
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    pub(super) fn accept_inbound_generation(
        &mut self,
        contact_id: ContactId,
        payload: Vec<u8>,
    ) -> HydraResult<Vec<u8>> {
        let content = generation_bound_content(&payload)
            .ok_or(HydraMsgError::InvalidEncoding("state generation binding"))?;
        let generation_offset = GENERATION_BINDING_MAGIC.len();
        let generation = u64::from_be_bytes(
            payload[generation_offset..generation_offset + 8]
                .try_into()
                .expect("generation binding is fixed length"),
        );
        let rollback_floor = self
            .sessions
            .get(&contact_id)
            .map(|session| session.rollback_generation_floor)
            .ok_or(HydraMsgError::SessionNotFound)?;
        if generation < rollback_floor {
            self.burn_contact_session(contact_id);
            return Err(HydraMsgError::StateRollbackDetected);
        }
        self.peer_generation_floors
            .entry(contact_id)
            .and_modify(|floor| *floor = (*floor).max(generation))
            .or_insert(generation);
        Ok(content.to_vec())
    }

    pub(crate) fn burn_contact_session(&mut self, contact_id: ContactId) {
        self.remove_session_routes(contact_id);
        self.sessions.remove(&contact_id);
        self.pending_offers
            .retain(|_, pending| pending.contact_id != contact_id);
        self.accepted_inits
            .retain(|_, accepted| accepted.contact_id != contact_id);
    }

    pub(crate) fn burn_all_sessions(&mut self) {
        let contacts = self.sessions.keys().copied().collect::<Vec<_>>();
        for contact_id in contacts {
            self.remove_session_routes(contact_id);
        }
        self.sessions.clear();
        self.pending_offers.clear();
        self.accepted_inits.clear();
    }
}
