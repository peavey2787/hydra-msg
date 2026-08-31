use crate::{
    codec::*,
    limits::{MAX_CONTACTS, MAX_STATE_SNAPSHOT_BYTES},
    ContactId, Hydra, HydraMsgError, HydraResult, HydraSessionSecurityPolicy, STATE_SNAPSHOT_MAGIC,
};
use std::collections::HashSet;

const MAX_STATE_SNAPSHOT_LINE_BYTES: usize = MAX_STATE_SNAPSHOT_BYTES;

pub(super) fn append_snapshot_line(out: &mut Vec<u8>, line: &str) -> HydraResult<()> {
    if line.len() > MAX_STATE_SNAPSHOT_LINE_BYTES {
        return Err(HydraMsgError::InvalidInput("state snapshot line length"));
    }
    append_snapshot_bytes(out, line.as_bytes())?;
    append_snapshot_bytes(out, b"\n")
}

pub(super) fn append_snapshot_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> HydraResult<()> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|total| total > MAX_STATE_SNAPSHOT_BYTES)
    {
        return Err(HydraMsgError::InvalidInput("state snapshot size"));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

pub(super) fn state_snapshot_text(bytes: &[u8]) -> HydraResult<&str> {
    if bytes.len() > MAX_STATE_SNAPSHOT_BYTES {
        return Err(HydraMsgError::InvalidEncoding("state snapshot size"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("state snapshot utf-8"))?;
    if !text.starts_with(std::str::from_utf8(STATE_SNAPSHOT_MAGIC).unwrap_or_default()) {
        return Err(HydraMsgError::InvalidEncoding("state snapshot magic"));
    }
    for line in text.lines() {
        if line.len() > MAX_STATE_SNAPSHOT_LINE_BYTES {
            return Err(HydraMsgError::InvalidEncoding("state snapshot line length"));
        }
    }
    Ok(text)
}

pub(super) fn required_snapshot_value<'a>(
    value: Option<&'a str>,
    description: &'static str,
) -> HydraResult<&'a str> {
    value.ok_or(HydraMsgError::InvalidEncoding(description))
}

pub(super) fn reject_extra_snapshot_fields(
    value: Option<&str>,
    description: &'static str,
) -> HydraResult<()> {
    if value.is_some() {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn reject_duplicate_scalar(
    saw_record: bool,
    description: &'static str,
) -> HydraResult<()> {
    if saw_record {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn reject_collection_limit(
    current_count: usize,
    max_count: usize,
    description: &'static str,
) -> HydraResult<()> {
    if current_count >= max_count {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn reject_runtime_collection_size(
    current_count: usize,
    max_count: usize,
    description: &'static str,
) -> HydraResult<()> {
    if current_count > max_count {
        return Err(HydraMsgError::InvalidInput(description));
    }
    Ok(())
}

pub(super) fn reject_duplicate_collection_record(
    inserted: bool,
    description: &'static str,
) -> HydraResult<()> {
    if !inserted {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn validate_peer_generation_floor<'a>(
    parts: &mut impl Iterator<Item = &'a str>,
    seen: &mut HashSet<ContactId>,
) -> HydraResult<()> {
    reject_collection_limit(
        seen.len(),
        MAX_CONTACTS,
        "state peer generation floor count",
    )?;
    let contact_hex = required_snapshot_value(parts.next(), "state peer generation floor contact")?;
    let generation = required_snapshot_value(parts.next(), "state peer generation floor value")?;
    reject_extra_snapshot_fields(parts.next(), "state peer generation floor")?;
    let contact_id = ContactId::from_hex(contact_hex)?;
    let _: u64 = generation
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("state peer generation floor value"))?;
    reject_duplicate_collection_record(
        seen.insert(contact_id),
        "state peer generation floor duplicate",
    )
}

pub(super) fn apply_state_snapshot_line(hydra: &mut Hydra, line: &str) -> HydraResult<()> {
    let mut parts = line.split('\t');
    match parts.next() {
        Some("state_generation") => {
            let value = required_snapshot_value(parts.next(), "state generation")?;
            hydra.state_generation = value
                .parse()
                .map_err(|_| HydraMsgError::InvalidEncoding("state generation"))?;
        }
        Some("next_message_id") => {
            let value = required_snapshot_value(parts.next(), "state next_message_id")?;
            hydra.next_message_id = value
                .parse()
                .map_err(|_| HydraMsgError::InvalidEncoding("state next_message_id"))?;
        }
        Some("anonymous_auth_secret") => {
            let value = required_snapshot_value(parts.next(), "state anonymous auth secret")?;
            hydra.anonymous_auth_secret = decode_anonymous_auth_secret(value)?;
        }
        Some("anonymous_auth_spent") => {
            let value = required_snapshot_value(parts.next(), "state anonymous auth spent")?;
            let nullifier = decode_anonymous_auth_spent(value)?;
            hydra.anonymous_auth_spent.push(nullifier);
            hydra.anonymous_auth_spent_index.insert(nullifier);
        }
        Some("identity") => {
            let record = decode_identity_line(line)?;
            hydra.identities.insert(record.id, record);
        }
        Some("contact") => {
            let contact = decode_contact_line(line)?;
            hydra.contacts.insert(contact.id, contact);
        }
        Some("session_security_policy") => {
            let contact_hex =
                required_snapshot_value(parts.next(), "state session security policy contact")?;
            let policy_value =
                required_snapshot_value(parts.next(), "state session security policy value")?;
            let contact_id = ContactId::from_hex(contact_hex)?;
            let policy = HydraSessionSecurityPolicy::from_snapshot_value(policy_value)?;
            hydra.session_security_policies.insert(contact_id, policy);
        }
        Some("peer_generation_floor") => {
            let contact_hex =
                required_snapshot_value(parts.next(), "state peer generation floor contact")?;
            let generation =
                required_snapshot_value(parts.next(), "state peer generation floor value")?;
            let contact_id = ContactId::from_hex(contact_hex)?;
            let generation = generation
                .parse()
                .map_err(|_| HydraMsgError::InvalidEncoding("state peer generation floor value"))?;
            hydra.peer_generation_floors.insert(contact_id, generation);
        }
        Some("message") => {
            let message = decode_message_line(line)?;
            hydra.next_message_id = hydra.next_message_id.max(message.id.0.saturating_add(1));
            hydra.messages.push(message);
        }
        Some("lobby") => {
            let lobby = decode_lobby_line(line)?;
            hydra.lobbies.insert(lobby.id, lobby);
        }
        _ => return Err(HydraMsgError::InvalidEncoding("state record kind")),
    }
    Ok(())
}
