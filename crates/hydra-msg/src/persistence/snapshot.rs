mod helpers;

use helpers::*;

use crate::{
    codec::*,
    limits::{
        MAX_ANONYMOUS_AUTH_SPENT, MAX_CONTACTS, MAX_IDENTITIES, MAX_LOBBIES, MAX_MESSAGES,
        MAX_MESSAGES_PER_CONTACT, MAX_STORED_MESSAGE_BYTES, MAX_STORED_MESSAGE_BYTES_PER_CONTACT,
    },
    Hydra, HydraMsgError, HydraResult, STATE_SNAPSHOT_MAGIC,
};
use std::collections::{HashMap, HashSet};

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
        let mut saw_state_generation = false;
        let mut saw_next_message_id = false;
        let mut saw_anonymous_auth_secret = false;
        let mut identity_ids = HashSet::new();
        let mut contact_ids = HashSet::new();
        let mut message_ids = HashSet::new();
        let mut lobby_ids = HashSet::new();
        let mut anonymous_auth_spent = HashSet::new();
        let mut messages_per_contact = HashMap::<_, (usize, usize)>::new();
        let mut total_message_bytes = 0usize;
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split('\t');
            match parts.next() {
                Some("state_generation") => {
                    reject_duplicate_scalar(saw_state_generation, "state generation")?;
                    let value = required_snapshot_value(parts.next(), "state generation")?;
                    reject_extra_snapshot_fields(parts.next(), "state generation")?;
                    let _: u64 = value
                        .parse()
                        .map_err(|_| HydraMsgError::InvalidEncoding("state generation"))?;
                    saw_state_generation = true;
                }
                Some("next_message_id") => {
                    reject_duplicate_scalar(saw_next_message_id, "state next_message_id")?;
                    let value = required_snapshot_value(parts.next(), "state next_message_id")?;
                    reject_extra_snapshot_fields(parts.next(), "state next_message_id")?;
                    let _: u64 = value
                        .parse()
                        .map_err(|_| HydraMsgError::InvalidEncoding("state next_message_id"))?;
                    saw_next_message_id = true;
                }
                Some("anonymous_auth_secret") => {
                    reject_duplicate_scalar(
                        saw_anonymous_auth_secret,
                        "state anonymous auth secret",
                    )?;
                    let value =
                        required_snapshot_value(parts.next(), "state anonymous auth secret")?;
                    reject_extra_snapshot_fields(parts.next(), "state anonymous auth secret")?;
                    let _ = decode_anonymous_auth_secret(value)?;
                    saw_anonymous_auth_secret = true;
                }
                Some("anonymous_auth_spent") => {
                    reject_collection_limit(
                        anonymous_auth_spent.len(),
                        MAX_ANONYMOUS_AUTH_SPENT,
                        "state anonymous auth spent count",
                    )?;
                    let value =
                        required_snapshot_value(parts.next(), "state anonymous auth spent")?;
                    reject_extra_snapshot_fields(parts.next(), "state anonymous auth spent")?;
                    let nullifier = decode_anonymous_auth_spent(value)?;
                    reject_duplicate_collection_record(
                        anonymous_auth_spent.insert(nullifier),
                        "state anonymous auth spent duplicate",
                    )?;
                }
                Some("identity") => {
                    reject_collection_limit(
                        identity_ids.len(),
                        MAX_IDENTITIES,
                        "state identity count",
                    )?;
                    let record = decode_identity_line(line)?;
                    reject_duplicate_collection_record(
                        identity_ids.insert(record.id),
                        "state identity duplicate",
                    )?;
                }
                Some("contact") => {
                    reject_collection_limit(
                        contact_ids.len(),
                        MAX_CONTACTS,
                        "state contact count",
                    )?;
                    let contact = decode_contact_line(line)?;
                    reject_duplicate_collection_record(
                        contact_ids.insert(contact.id),
                        "state contact duplicate",
                    )?;
                }
                Some("message") => {
                    reject_collection_limit(
                        message_ids.len(),
                        MAX_MESSAGES,
                        "state message count",
                    )?;
                    let message = decode_message_line(line)?;
                    reject_duplicate_collection_record(
                        message_ids.insert(message.id),
                        "state message duplicate",
                    )?;
                    let size = stored_message_size(&message.plaintext, &message.attachments)?;
                    total_message_bytes = total_message_bytes.checked_add(size).ok_or(
                        HydraMsgError::InvalidEncoding("state stored message byte count"),
                    )?;
                    if total_message_bytes > MAX_STORED_MESSAGE_BYTES {
                        return Err(HydraMsgError::InvalidEncoding(
                            "state stored message byte limit",
                        ));
                    }
                    let usage = messages_per_contact
                        .entry(message.contact_id)
                        .or_insert((0usize, 0usize));
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
                }
                Some("lobby") => {
                    reject_collection_limit(lobby_ids.len(), MAX_LOBBIES, "state lobby count")?;
                    let lobby = decode_lobby_line(line)?;
                    reject_duplicate_collection_record(
                        lobby_ids.insert(lobby.id),
                        "state lobby duplicate",
                    )?;
                }
                _ => return Err(HydraMsgError::InvalidEncoding("state record kind")),
            }
        }
        if !saw_state_generation {
            return Err(HydraMsgError::InvalidEncoding("state generation"));
        }
        if !saw_next_message_id {
            return Err(HydraMsgError::InvalidEncoding("state next_message_id"));
        }
        if !saw_anonymous_auth_secret {
            return Err(HydraMsgError::InvalidEncoding(
                "state anonymous auth secret",
            ));
        }
        Ok(())
    }

    pub(crate) fn apply_state_snapshot(&mut self, bytes: &[u8]) -> HydraResult<()> {
        Self::verify_state_snapshot(bytes)?;
        let text = state_snapshot_text(bytes)?;
        self.identities.clear();
        self.active_id = None;
        self.contacts.clear();
        self.pending_offers.clear();
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
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split('\t');
            match parts.next() {
                Some("state_generation") => {
                    let value = required_snapshot_value(parts.next(), "state generation")?;
                    self.state_generation = value
                        .parse()
                        .map_err(|_| HydraMsgError::InvalidEncoding("state generation"))?;
                }
                Some("next_message_id") => {
                    let value = required_snapshot_value(parts.next(), "state next_message_id")?;
                    self.next_message_id = value
                        .parse()
                        .map_err(|_| HydraMsgError::InvalidEncoding("state next_message_id"))?;
                }
                Some("anonymous_auth_secret") => {
                    let value =
                        required_snapshot_value(parts.next(), "state anonymous auth secret")?;
                    self.anonymous_auth_secret = decode_anonymous_auth_secret(value)?;
                }
                Some("anonymous_auth_spent") => {
                    let value =
                        required_snapshot_value(parts.next(), "state anonymous auth spent")?;
                    let nullifier = decode_anonymous_auth_spent(value)?;
                    self.anonymous_auth_spent.push(nullifier);
                    self.anonymous_auth_spent_index.insert(nullifier);
                }
                Some("identity") => {
                    let record = decode_identity_line(line)?;
                    self.identities.insert(record.id, record);
                }
                Some("contact") => {
                    let contact = decode_contact_line(line)?;
                    self.contacts.insert(contact.id, contact);
                }
                Some("message") => {
                    let message = decode_message_line(line)?;
                    self.next_message_id = self.next_message_id.max(message.id.0.saturating_add(1));
                    self.messages.push(message);
                }
                Some("lobby") => {
                    let lobby = decode_lobby_line(line)?;
                    self.lobbies.insert(lobby.id, lobby);
                }
                _ => return Err(HydraMsgError::InvalidEncoding("state record kind")),
            }
        }
        self.rebuild_message_usage()?;
        Ok(())
    }
}
