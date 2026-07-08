use super::{exact_array_from_vec, hex_decode, hex_encode, write_u64, BytesReader};
use crate::{
    ContactId, HydraLobby, HydraLobbyPolicy, HydraMsgError, HydraResult, LobbyId,
    LOBBY_INVITE_MAGIC, LOBBY_PAYLOAD_MAGIC,
};
use hydra_core::HASH_SIZE;
use hydra_group::GroupMode;

pub(super) fn validate_lobby_policy(policy: &HydraLobbyPolicy) -> HydraResult<()> {
    if policy.label.trim().is_empty() {
        return Err(HydraMsgError::InvalidInput("lobby label is empty"));
    }
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
    Ok(())
}

pub(super) fn encode_lobby_line(lobby: &HydraLobby) -> String {
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
    .join("	")
}

pub(super) fn decode_lobby_line(line: &str) -> HydraResult<HydraLobby> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "lobby" {
        return Err(HydraMsgError::InvalidEncoding("lobby state record"));
    }
    let id = LobbyId(exact_array_from_vec(hex_decode(parts[1])?)?);
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby label"))?;
    let max_members = parts[3]
        .parse()
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby max_members"))?;
    let members = if parts[4].is_empty() {
        Vec::new()
    } else {
        parts[4]
            .split(',')
            .map(|member| Ok(ContactId(exact_array_from_vec(hex_decode(member)?)?)))
            .collect::<HydraResult<Vec<_>>>()?
    };
    Ok(HydraLobby {
        id,
        policy: HydraLobbyPolicy::new(label, max_members),
        members,
    })
}

pub(super) fn encode_lobby_invite(lobby: &HydraLobby, members: &[ContactId]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(LOBBY_INVITE_MAGIC.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"id:");
    out.extend_from_slice(lobby.id.hex().as_bytes());
    out.extend_from_slice(b"\nlabel:");
    out.extend_from_slice(hex_encode(lobby.policy.label.as_bytes()).as_bytes());
    out.extend_from_slice(b"\nmax_members:");
    out.extend_from_slice(lobby.policy.max_members.to_string().as_bytes());
    out.extend_from_slice(b"\nmembers:");
    out.extend_from_slice(
        members
            .iter()
            .map(|member| member.hex())
            .collect::<Vec<_>>()
            .join(",")
            .as_bytes(),
    );
    out.push(b'\n');
    out
}

pub(super) fn decode_lobby_invite(bytes: &[u8]) -> HydraResult<HydraLobby> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite is not utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(LOBBY_INVITE_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("lobby invite magic"));
    }

    // Backward-compatible decode for the older three-line placeholder invite.
    if let Some(first) = lines.next() {
        if !first.contains(':') {
            let id = LobbyId(exact_array_from_vec(hex_decode(first)?)?);
            let label = lines.next().unwrap_or("HYDRA lobby").to_string();
            return Ok(HydraLobby {
                id,
                policy: HydraLobbyPolicy::new(label, 64),
                members: Vec::new(),
            });
        }

        let mut id = None;
        let mut label = None;
        let mut max_members = None;
        let mut members = Vec::new();
        for line in std::iter::once(first).chain(lines) {
            if let Some(value) = line.strip_prefix("id:") {
                id = Some(LobbyId(exact_array_from_vec(hex_decode(value)?)?));
            } else if let Some(value) = line.strip_prefix("label:") {
                label = Some(
                    String::from_utf8(hex_decode(value)?)
                        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite label"))?,
                );
            } else if let Some(value) = line.strip_prefix("max_members:") {
                max_members = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| HydraMsgError::InvalidEncoding("lobby invite max_members"))?,
                );
            } else if let Some(value) = line.strip_prefix("members:") {
                if !value.trim().is_empty() {
                    members = value
                        .split(',')
                        .map(|member| Ok(ContactId(exact_array_from_vec(hex_decode(member)?)?)))
                        .collect::<HydraResult<Vec<_>>>()?;
                }
            }
        }
        let policy = HydraLobbyPolicy::new(
            label.unwrap_or_else(|| "HYDRA lobby".to_string()),
            max_members.unwrap_or(64),
        );
        return Ok(HydraLobby {
            id: id.ok_or(HydraMsgError::InvalidEncoding("lobby invite id"))?,
            policy,
            members,
        });
    }
    Err(HydraMsgError::InvalidEncoding("lobby invite id"))
}

pub(super) fn pack_lobby_payload(lobby_id: LobbyId, packed_message: &[u8]) -> HydraResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(LOBBY_PAYLOAD_MAGIC);
    out.extend_from_slice(&lobby_id.0);
    write_u64(&mut out, packed_message.len() as u64);
    out.extend_from_slice(packed_message);
    Ok(out)
}

pub(super) fn unpack_lobby_payload(bytes: &[u8]) -> HydraResult<(LobbyId, Vec<u8>)> {
    let mut reader = BytesReader::new(bytes);
    reader.expect(LOBBY_PAYLOAD_MAGIC)?;
    let lobby_id = LobbyId(exact_array_from_vec(reader.read(HASH_SIZE)?.to_vec())?);
    let message_len = reader.read_u64()? as usize;
    let packed_message = reader.read_vec(message_len)?;
    Ok((lobby_id, packed_message))
}
