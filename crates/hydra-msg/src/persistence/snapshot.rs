mod helpers;

use helpers::*;

use crate::{
    codec::*,
    limits::{
        MAX_ANONYMOUS_AUTH_SPENT, MAX_CONTACTS, MAX_IDENTITIES, MAX_LOBBIES, MAX_MESSAGES,
        MAX_MESSAGES_PER_CONTACT, MAX_STORED_MESSAGE_BYTES, MAX_STORED_MESSAGE_BYTES_PER_CONTACT,
    },
    ContactId, Hydra, HydraAnonymousAuthNullifier, HydraMsgError, HydraResult,
    HydraSessionSecurityPolicy, IdentityId, LobbyId, MessageId, STATE_SNAPSHOT_MAGIC,
};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
struct SnapshotValidationState {
    saw_state_generation: bool,
    saw_next_message_id: bool,
    saw_anonymous_auth_secret: bool,
    identity_ids: HashSet<IdentityId>,
    contact_ids: HashSet<ContactId>,
    session_security_policy_ids: HashSet<ContactId>,
    peer_generation_floor_ids: HashSet<ContactId>,
    message_ids: HashSet<MessageId>,
    lobby_ids: HashSet<LobbyId>,
    anonymous_auth_spent: HashSet<HydraAnonymousAuthNullifier>,
    messages_per_contact: HashMap<ContactId, (usize, usize)>,
    total_message_bytes: usize,
}

impl SnapshotValidationState {
    fn validate_line(&mut self, line: &str) -> HydraResult<()> {
        let mut parts = line.split('\t');
        match parts.next() {
            Some("state_generation") => validate_u64_scalar(
                &mut parts,
                &mut self.saw_state_generation,
                "state generation",
            ),
            Some("next_message_id") => validate_u64_scalar(
                &mut parts,
                &mut self.saw_next_message_id,
                "state next_message_id",
            ),
            Some("anonymous_auth_secret") => validate_anonymous_auth_secret_scalar(
                &mut parts,
                &mut self.saw_anonymous_auth_secret,
            ),
            Some("anonymous_auth_spent") => self.validate_anonymous_auth_spent(&mut parts),
            Some("identity") => self.validate_identity(line),
            Some("contact") => self.validate_contact(line),
            Some("session_security_policy") => self.validate_session_security_policy(&mut parts),
            Some("peer_generation_floor") => {
                validate_peer_generation_floor(&mut parts, &mut self.peer_generation_floor_ids)
            }
            Some("message") => self.validate_message(line),
            Some("lobby") => self.validate_lobby(line),
            _ => Err(HydraMsgError::InvalidEncoding("state record kind")),
        }
    }

    fn validate_anonymous_auth_spent<'a>(
        &mut self,
        parts: &mut impl Iterator<Item = &'a str>,
    ) -> HydraResult<()> {
        reject_collection_limit(
            self.anonymous_auth_spent.len(),
            MAX_ANONYMOUS_AUTH_SPENT,
            "state anonymous auth spent count",
        )?;
        let value = required_snapshot_value(parts.next(), "state anonymous auth spent")?;
        reject_extra_snapshot_fields(parts.next(), "state anonymous auth spent")?;
        let nullifier = decode_anonymous_auth_spent(value)?;
        reject_duplicate_collection_record(
            self.anonymous_auth_spent.insert(nullifier),
            "state anonymous auth spent duplicate",
        )
    }

    fn validate_identity(&mut self, line: &str) -> HydraResult<()> {
        reject_collection_limit(
            self.identity_ids.len(),
            MAX_IDENTITIES,
            "state identity count",
        )?;
        let record = decode_identity_line(line)?;
        reject_duplicate_collection_record(
            self.identity_ids.insert(record.id),
            "state identity duplicate",
        )
    }

    fn validate_contact(&mut self, line: &str) -> HydraResult<()> {
        reject_collection_limit(self.contact_ids.len(), MAX_CONTACTS, "state contact count")?;
        let contact = decode_contact_line(line)?;
        reject_duplicate_collection_record(
            self.contact_ids.insert(contact.id),
            "state contact duplicate",
        )
    }

    fn validate_session_security_policy<'a>(
        &mut self,
        parts: &mut impl Iterator<Item = &'a str>,
    ) -> HydraResult<()> {
        reject_collection_limit(
            self.session_security_policy_ids.len(),
            MAX_CONTACTS,
            "state session security policy count",
        )?;
        let contact_hex =
            required_snapshot_value(parts.next(), "state session security policy contact")?;
        let policy_value =
            required_snapshot_value(parts.next(), "state session security policy value")?;
        reject_extra_snapshot_fields(parts.next(), "state session security policy")?;
        let contact_id = ContactId::from_hex(contact_hex)?;
        let _ = HydraSessionSecurityPolicy::from_snapshot_value(policy_value)?;
        reject_duplicate_collection_record(
            self.session_security_policy_ids.insert(contact_id),
            "state session security policy duplicate",
        )
    }

    fn validate_message(&mut self, line: &str) -> HydraResult<()> {
        reject_collection_limit(self.message_ids.len(), MAX_MESSAGES, "state message count")?;
        let message = decode_message_line(line)?;
        reject_duplicate_collection_record(
            self.message_ids.insert(message.id),
            "state message duplicate",
        )?;
        let size = stored_message_size(&message.plaintext, &message.attachments)?;
        self.total_message_bytes =
            self.total_message_bytes
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidEncoding(
                    "state stored message byte count",
                ))?;
        if self.total_message_bytes > MAX_STORED_MESSAGE_BYTES {
            return Err(HydraMsgError::InvalidEncoding(
                "state stored message byte limit",
            ));
        }
        validate_message_contact_usage(&mut self.messages_per_contact, message.contact_id, size)
    }

    fn validate_lobby(&mut self, line: &str) -> HydraResult<()> {
        reject_collection_limit(self.lobby_ids.len(), MAX_LOBBIES, "state lobby count")?;
        let lobby = decode_lobby_line(line)?;
        reject_duplicate_collection_record(self.lobby_ids.insert(lobby.id), "state lobby duplicate")
    }

    fn finish(self) -> HydraResult<()> {
        if self
            .session_security_policy_ids
            .iter()
            .any(|contact_id| !self.contact_ids.contains(contact_id))
        {
            return Err(HydraMsgError::InvalidEncoding(
                "state session security policy contact",
            ));
        }
        if self
            .peer_generation_floor_ids
            .iter()
            .any(|contact_id| !self.contact_ids.contains(contact_id))
        {
            return Err(HydraMsgError::InvalidEncoding(
                "state peer generation floor contact",
            ));
        }
        if !self.saw_state_generation {
            return Err(HydraMsgError::InvalidEncoding("state generation"));
        }
        if !self.saw_next_message_id {
            return Err(HydraMsgError::InvalidEncoding("state next_message_id"));
        }
        if !self.saw_anonymous_auth_secret {
            return Err(HydraMsgError::InvalidEncoding(
                "state anonymous auth secret",
            ));
        }
        Ok(())
    }
}

fn validate_u64_scalar<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    saw: &mut bool,
    label: &'static str,
) -> HydraResult<()> {
    reject_duplicate_scalar(*saw, label)?;
    let value = required_snapshot_value(parts.next(), label)?;
    reject_extra_snapshot_fields(parts.next(), label)?;
    let _: u64 = value
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding(label))?;
    *saw = true;
    Ok(())
}

fn validate_anonymous_auth_secret_scalar<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    saw: &mut bool,
) -> HydraResult<()> {
    let label = "state anonymous auth secret";
    reject_duplicate_scalar(*saw, label)?;
    let value = required_snapshot_value(parts.next(), label)?;
    reject_extra_snapshot_fields(parts.next(), label)?;
    let _ = decode_anonymous_auth_secret(value)?;
    *saw = true;
    Ok(())
}

fn validate_message_contact_usage(
    usage_by_contact: &mut HashMap<ContactId, (usize, usize)>,
    contact_id: ContactId,
    size: usize,
) -> HydraResult<()> {
    let usage = usage_by_contact.entry(contact_id).or_insert((0, 0));
    reject_collection_limit(
        usage.0,
        MAX_MESSAGES_PER_CONTACT,
        "state messages per contact count",
    )?;
    usage.0 += 1;
    usage.1 = usage
        .1
        .checked_add(size)
        .ok_or(HydraMsgError::InvalidEncoding(
            "state stored message byte count",
        ))?;
    if usage.1 > MAX_STORED_MESSAGE_BYTES_PER_CONTACT {
        return Err(HydraMsgError::InvalidEncoding(
            "state message bytes per contact limit",
        ));
    }
    Ok(())
}

impl Hydra {
    pub(crate) fn encode_state_snapshot(&self) -> HydraResult<Vec<u8>> {
        reject_runtime_collection_size(self.identities.len(), MAX_IDENTITIES, "identity limit")?;
        reject_runtime_collection_size(self.contacts.len(), MAX_CONTACTS, "contact limit")?;
        reject_runtime_collection_size(self.messages.len(), MAX_MESSAGES, "message limit")?;
        reject_runtime_collection_size(self.lobbies.len(), MAX_LOBBIES, "lobby limit")?;
        reject_runtime_collection_size(
            self.anonymous_auth_spent.len(),
            MAX_ANONYMOUS_AUTH_SPENT,
            "anonymous authorization spent limit",
        )?;
        let mut total_message_bytes = 0usize;
        let mut per_contact = HashMap::<_, (usize, usize)>::new();
        for message in &self.messages {
            let size = stored_message_size(&message.plaintext, &message.attachments)?;
            total_message_bytes = total_message_bytes
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidInput("stored message byte count"))?;
            reject_runtime_collection_size(
                total_message_bytes,
                MAX_STORED_MESSAGE_BYTES,
                "stored message byte limit",
            )?;
            let usage = per_contact
                .entry(message.contact_id)
                .or_insert((0usize, 0usize));
            usage.0 += 1;
            usage.1 = usage
                .1
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidInput("stored message byte count"))?;
            reject_runtime_collection_size(
                usage.0,
                MAX_MESSAGES_PER_CONTACT,
                "messages per contact limit",
            )?;
            reject_runtime_collection_size(
                usage.1,
                MAX_STORED_MESSAGE_BYTES_PER_CONTACT,
                "message bytes per contact limit",
            )?;
        }

        let mut out = Vec::new();
        append_snapshot_bytes(&mut out, STATE_SNAPSHOT_MAGIC)?;
        append_snapshot_line(
            &mut out,
            &format!("state_generation\t{}", self.state_generation),
        )?;
        append_snapshot_line(
            &mut out,
            &format!("next_message_id\t{}", self.next_message_id),
        )?;
        append_snapshot_line(
            &mut out,
            &format!(
                "anonymous_auth_secret\t{}",
                encode_anonymous_auth_secret(&self.anonymous_auth_secret)
            ),
        )?;
        for nullifier in &self.anonymous_auth_spent {
            append_snapshot_line(
                &mut out,
                &format!(
                    "anonymous_auth_spent\t{}",
                    encode_anonymous_auth_spent(*nullifier)
                ),
            )?;
        }
        for record in self.identities.values() {
            append_snapshot_line(&mut out, &encode_identity_line(record))?;
        }
        for contact in self.contacts.values() {
            append_snapshot_line(&mut out, &encode_contact_line(contact))?;
        }
        for (contact_id, policy) in &self.session_security_policies {
            append_snapshot_line(
                &mut out,
                &format!(
                    "session_security_policy\t{}\t{}",
                    contact_id.hex(),
                    policy.snapshot_value()
                ),
            )?;
        }
        for (contact_id, generation) in &self.peer_generation_floors {
            append_snapshot_line(
                &mut out,
                &format!(
                    "peer_generation_floor\t{}\t{}",
                    contact_id.hex(),
                    generation
                ),
            )?;
        }
        for message in &self.messages {
            append_snapshot_line(&mut out, &encode_message_line(message))?;
        }
        for lobby in self.lobbies.values() {
            append_snapshot_line(&mut out, &encode_lobby_line(lobby))?;
        }
        Ok(out)
    }

    pub(crate) fn verify_state_snapshot(bytes: &[u8]) -> HydraResult<()> {
        let text = state_snapshot_text(bytes)?;
        let mut validation = SnapshotValidationState::default();
        for line in text.lines().skip(1) {
            if !line.trim().is_empty() {
                validation.validate_line(line)?;
            }
        }
        validation.finish()
    }

    fn clear_state_for_snapshot_apply(&mut self) {
        self.identities.clear();
        self.active_id = None;
        self.contacts.clear();
        self.session_security_policies.clear();
        self.peer_generation_floors.clear();
        self.pending_offers.clear();
        self.accepted_inits.clear();
        self.sessions.clear();
        self.receive_routes.clear();
        self.session_route_tags.clear();
        self.messages.clear();
        self.message_usage.clear();
        self.stored_message_bytes = 0;
        self.lobbies.clear();
        self.anonymous_auth_spent.clear();
        self.anonymous_auth_spent_index.clear();
        self.pending_fragments.clear();
        self.next_message_id = 1;
        self.state_generation = 0;
    }

    pub(crate) fn apply_state_snapshot(&mut self, bytes: &[u8]) -> HydraResult<()> {
        Self::verify_state_snapshot(bytes)?;
        let text = state_snapshot_text(bytes)?;
        self.clear_state_for_snapshot_apply();
        for line in text.lines().skip(1) {
            if !line.trim().is_empty() {
                apply_state_snapshot_line(self, line)?;
            }
        }
        self.rebuild_message_usage()?;
        Ok(())
    }
}
