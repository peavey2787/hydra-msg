use super::SessionRecord;
use crate::{
    limits::{MAX_SESSION_ROUTE_TAGS, MAX_SESSION_ROUTE_TAGS_PER_SESSION},
    ContactId, Hydra, HydraMsgError, HydraResult,
};
use hydra_envelope::decode_outer_header;
use hydra_session::{SessionError, SessionState};
use std::collections::HashSet;

impl Hydra {
    pub(super) fn receive_route_candidates(&self, envelope: &[u8]) -> HydraResult<Vec<ContactId>> {
        let header = decode_outer_header(envelope)
            .map_err(|_| HydraMsgError::Session(SessionError::InvalidEnvelope.to_string()))?;
        Ok(self
            .receive_routes
            .get(&header.route_tag)
            .cloned()
            .unwrap_or_default())
    }

    pub(super) fn install_session(
        &mut self,
        contact_id: ContactId,
        state: SessionState,
    ) -> HydraResult<()> {
        let route_tags = state.candidate_receive_route_tags()?;
        self.install_session_route_tags(contact_id, route_tags)?;
        self.sessions.insert(
            contact_id,
            SessionRecord {
                state,
                closed: false,
            },
        );
        Ok(())
    }

    pub(crate) fn refresh_session_routes(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let route_tags = match self.sessions.get(&contact_id) {
            Some(session) if !session.closed => session.state.candidate_receive_route_tags()?,
            _ => {
                self.remove_session_routes(contact_id);
                return Ok(());
            }
        };
        self.install_session_route_tags(contact_id, route_tags)
    }

    fn install_session_route_tags(
        &mut self,
        contact_id: ContactId,
        route_tags: Vec<[u8; 16]>,
    ) -> HydraResult<()> {
        if route_tags.len() > MAX_SESSION_ROUTE_TAGS_PER_SESSION {
            return Err(HydraMsgError::InvalidInput("session receive-route limit"));
        }
        let unique_tags = route_tags.into_iter().collect::<HashSet<_>>();
        let existing_count = self.session_route_tags.get(&contact_id).map_or(0, Vec::len);
        let indexed_count = self
            .session_route_tags
            .values()
            .try_fold(0usize, |total, tags| total.checked_add(tags.len()))
            .ok_or(HydraMsgError::InvalidInput("session receive-route count"))?;
        let new_total = indexed_count
            .checked_sub(existing_count)
            .and_then(|total| total.checked_add(unique_tags.len()))
            .ok_or(HydraMsgError::InvalidInput("session receive-route count"))?;
        if new_total > MAX_SESSION_ROUTE_TAGS {
            return Err(HydraMsgError::InvalidInput("session receive-route limit"));
        }

        self.remove_session_routes(contact_id);
        let mut stored_tags = Vec::with_capacity(unique_tags.len());
        for route_tag in unique_tags {
            let contacts = self.receive_routes.entry(route_tag).or_default();
            if !contacts.contains(&contact_id) {
                contacts.push(contact_id);
            }
            stored_tags.push(route_tag);
        }
        self.session_route_tags.insert(contact_id, stored_tags);
        Ok(())
    }

    pub(crate) fn remove_session_routes(&mut self, contact_id: ContactId) {
        let Some(route_tags) = self.session_route_tags.remove(&contact_id) else {
            return;
        };
        for route_tag in route_tags {
            let remove_bucket = if let Some(contacts) = self.receive_routes.get_mut(&route_tag) {
                contacts.retain(|existing| *existing != contact_id);
                contacts.is_empty()
            } else {
                false
            };
            if remove_bucket {
                self.receive_routes.remove(&route_tag);
            }
        }
    }
}
