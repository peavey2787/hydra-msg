use super::{exact_array_from_vec, hex_decode, hex_encode, write_u64, BytesReader};
use crate::{
    limits::{
        reject_encoded_size, validate_label_encoding, MAX_FRAGMENTED_PAYLOAD_BYTES,
        MAX_LABEL_BYTES, MAX_LOBBY_INVITE_BYTES, MAX_PACKED_MESSAGE_BYTES,
    },
    ContactId, HydraLobby, HydraLobbyPolicy, HydraMsgError, HydraResult, LobbyId,
    LOBBY_INVITE_MAGIC, LOBBY_PAYLOAD_MAGIC,
};
use hydra_core::HASH_SIZE;
use hydra_group::GroupMode;
use std::collections::HashSet;

pub(crate) fn validate_lobby_policy(policy: &HydraLobbyPolicy) -> HydraResult<()> {
    if policy.max_members == 0 {
        return Err(HydraMsgError::InvalidInput(
            "lobby max_members must be greater than zero",
        ));
    }
    if policy.max_members > GroupMode::Interactive.max_roster_entries() {
        return Err(HydraMsgError::InvalidInput(
            "lobby max_members exceeds HYDRA group limit",
        ));
    }
    crate::limits::validate_label_input(&policy.label, "lobby label size")
}

pub(crate) fn encode_lobby_line(lobby: &HydraLobby) -> String {
    let members = lobby
        .members
        .iter()
        .map(|member| member.hex())
        .collect::<Vec<_>>()
        .join(",");
    [
        "lobby".to_string(),
        hex_encode(&lobby.id.0),
        hex_encode(lobby.policy.label.as_bytes()),
        lobby.policy.max_members.to_string(),
        members,
    ]
    .join("\t")
}

pub(crate) fn decode_lobby_line(line: &str) -> HydraResult<HydraLobby> {
    let parts = line.split('\t').take(6).collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "lobby" {
        return Err(HydraMsgError::InvalidEncoding("lobby state record"));
    }
    if parts[1].len() != HASH_SIZE * 2 {
        return Err(HydraMsgError::InvalidEncoding("lobby id size"));
    }
    let id = LobbyId(exact_array_from_vec(hex_decode(parts[1])?)?);
    reject_encoded_size(parts[2].len(), MAX_LABEL_BYTES * 2, "lobby label size")?;
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby label"))?;
    validate_label_encoding(&label, "lobby label size")?;
    let max_members = parts[3]
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby max_members"))?;
    validate_decoded_lobby_member_limit(max_members)?;
    let members = decode_member_list(parts[4], max_members)?;
    Ok(HydraLobby {
        id,
        policy: HydraLobbyPolicy::new(label, max_members),
        members,
    })
}

pub(crate) fn encode_lobby_invite(
    lobby: &HydraLobby,
    include_label: bool,
    members: Option<&[ContactId]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(LOBBY_INVITE_MAGIC.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"id:");
    out.extend_from_slice(lobby.id.hex().as_bytes());
    out.extend_from_slice(b"\nmax_members:");
    out.extend_from_slice(lobby.policy.max_members.to_string().as_bytes());
    if include_label && !lobby.policy.label.trim().is_empty() {
        out.extend_from_slice(b"\nlabel:");
        out.extend_from_slice(hex_encode(lobby.policy.label.trim().as_bytes()).as_bytes());
    }
    if let Some(members) = members.filter(|members| !members.is_empty()) {
        out.extend_from_slice(b"\nmembers:");
        out.extend_from_slice(
            members
                .iter()
                .map(|member| member.hex())
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
        );
    }
    out.push(b'\n');
    out
}

pub(crate) fn decode_lobby_invite(bytes: &[u8]) -> HydraResult<HydraLobby> {
    reject_encoded_size(bytes.len(), MAX_LOBBY_INVITE_BYTES, "lobby invite size")?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite is not utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(LOBBY_INVITE_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("lobby invite magic"));
    }

    let mut id = None;
    let mut label = None;
    let mut max_members = None;
    let mut member_field = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("id:") {
            set_once(&mut id, parse_lobby_id(value)?, "lobby invite id")?;
        } else if let Some(value) = line.strip_prefix("label:") {
            reject_encoded_size(value.len(), MAX_LABEL_BYTES * 2, "lobby invite label size")?;
            let decoded = String::from_utf8(hex_decode(value)?)
                .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite label"))?;
            validate_label_encoding(&decoded, "lobby invite label size")?;
            set_once(&mut label, decoded, "lobby invite label")?;
        } else if let Some(value) = line.strip_prefix("max_members:") {
            let decoded = value
                .parse::<usize>()
                .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite max_members"))?;
            validate_decoded_lobby_member_limit(decoded)?;
            set_once(&mut max_members, decoded, "lobby invite max_members")?;
        } else if let Some(value) = line.strip_prefix("members:") {
            set_once(&mut member_field, value.to_string(), "lobby invite members")?;
        } else {
            return Err(HydraMsgError::InvalidEncoding("lobby invite field"));
        }
    }
    let max_members =
        max_members.ok_or(HydraMsgError::InvalidEncoding("lobby invite max_members"))?;
    let members = decode_member_list(member_field.as_deref().unwrap_or_default(), max_members)?;
    Ok(HydraLobby {
        id: id.ok_or(HydraMsgError::InvalidEncoding("lobby invite id"))?,
        policy: HydraLobbyPolicy::new(label.unwrap_or_default(), max_members),
        members,
    })
}

pub(crate) fn pack_lobby_payload(lobby_id: LobbyId, packed_message: &[u8]) -> HydraResult<Vec<u8>> {
    reject_encoded_size(
        packed_message.len(),
        MAX_PACKED_MESSAGE_BYTES,
        "packed lobby message size",
    )?;
    let capacity = LOBBY_PAYLOAD_MAGIC
        .len()
        .checked_add(HASH_SIZE)
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(packed_message.len()))
        .ok_or(HydraMsgError::InvalidInput("lobby payload size"))?;
    if capacity > MAX_FRAGMENTED_PAYLOAD_BYTES {
        return Err(HydraMsgError::InvalidInput("lobby payload size"));
    }
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(LOBBY_PAYLOAD_MAGIC);
    out.extend_from_slice(&lobby_id.0);
    write_u64(&mut out, packed_message.len() as u64);
    out.extend_from_slice(packed_message);
    Ok(out)
}

pub(crate) fn unpack_lobby_payload(bytes: &[u8]) -> HydraResult<(LobbyId, Vec<u8>)> {
    reject_encoded_size(
        bytes.len(),
        MAX_FRAGMENTED_PAYLOAD_BYTES,
        "lobby payload size",
    )?;
    let mut reader = BytesReader::new(bytes);
    reader.expect(LOBBY_PAYLOAD_MAGIC)?;
    let lobby_id = LobbyId(exact_array_from_vec(reader.read(HASH_SIZE)?.to_vec())?);
    let message_len = usize::try_from(reader.read_u64()?)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby message size"))?;
    reject_encoded_size(
        message_len,
        MAX_PACKED_MESSAGE_BYTES,
        "packed lobby message size",
    )?;
    let packed_message = reader.read_vec(message_len)?;
    if !reader.is_finished() {
        return Err(HydraMsgError::InvalidEncoding(
            "lobby payload trailing bytes",
        ));
    }
    Ok((lobby_id, packed_message))
}

fn parse_lobby_id(value: &str) -> HydraResult<LobbyId> {
    if value.len() != HASH_SIZE * 2 {
        return Err(HydraMsgError::InvalidEncoding("lobby invite id size"));
    }
    Ok(LobbyId(exact_array_from_vec(hex_decode(value)?)?))
}

fn decode_member_list(value: &str, max_members: usize) -> HydraResult<Vec<ContactId>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut members = Vec::new();
    let mut unique = HashSet::new();
    for member in value.split(',') {
        if members.len() >= max_members {
            return Err(HydraMsgError::InvalidEncoding("lobby member count"));
        }
        reject_encoded_size(member.len(), HASH_SIZE * 2, "lobby member id size")?;
        let contact_id = ContactId(exact_array_from_vec(hex_decode(member)?)?);
        if !unique.insert(contact_id) {
            return Err(HydraMsgError::InvalidEncoding("duplicate lobby member"));
        }
        members.push(contact_id);
    }
    Ok(members)
}

fn validate_decoded_lobby_member_limit(max_members: usize) -> HydraResult<()> {
    if max_members == 0 || max_members > GroupMode::Interactive.max_roster_entries() {
        return Err(HydraMsgError::InvalidEncoding("lobby max_members"));
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, description: &'static str) -> HydraResult<()> {
    if slot.is_some() {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    *slot = Some(value);
    Ok(())
}
