use crate::{codec::*, limits::MAX_FRAGMENTS_PER_MESSAGE, HydraMsgError, HydraResult, LobbyId};

pub(super) const FRAGMENT_MAGIC: &[u8] = b"HYDRA-MSG-FRAGMENT\n";
pub(super) const LEGACY_FRAGMENT_HEADER_BYTES: usize = FRAGMENT_MAGIC.len() + 1 + 32 + 4 + 4 + 4;
pub(super) const SCOPED_FRAGMENT_HEADER_BYTES: usize = LEGACY_FRAGMENT_HEADER_BYTES + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum FragmentKind {
    Direct,
    Lobby,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FragmentScope {
    Direct,
    Lobby(LobbyId),
}

pub(super) struct FragmentRecord {
    pub(super) kind: FragmentKind,
    pub(super) lobby_id: Option<LobbyId>,
    pub(super) fragment_id: [u8; 32],
    pub(super) total: usize,
    pub(super) index: usize,
    pub(super) bytes: Vec<u8>,
}

pub(super) fn payload_needs_fragment_record(payload: &[u8], max_payload_size: usize) -> bool {
    payload.len() > max_payload_size || payload.starts_with(FRAGMENT_MAGIC)
}

pub(super) const fn fragment_header_bytes(scope: FragmentScope) -> usize {
    match scope {
        FragmentScope::Direct => LEGACY_FRAGMENT_HEADER_BYTES,
        FragmentScope::Lobby(_) => SCOPED_FRAGMENT_HEADER_BYTES,
    }
}

pub(super) fn encode_fragment_record(
    scope: FragmentScope,
    fragment_id: [u8; 32],
    total: u32,
    index: u32,
    bytes: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(fragment_header_bytes(scope) + bytes.len());
    out.extend_from_slice(FRAGMENT_MAGIC);
    match scope {
        FragmentScope::Direct => out.push(1),
        FragmentScope::Lobby(lobby_id) => {
            out.push(3);
            out.extend_from_slice(&lobby_id.0);
        }
    }
    out.extend_from_slice(&fragment_id);
    write_u32(&mut out, total);
    write_u32(&mut out, index);
    write_u32(&mut out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    out
}

pub(super) fn decode_fragment_record(bytes: &[u8]) -> HydraResult<Option<FragmentRecord>> {
    if !bytes.starts_with(FRAGMENT_MAGIC) {
        return Ok(None);
    }
    let mut reader = BytesReader::new(bytes);
    reader.expect(FRAGMENT_MAGIC)?;
    let (kind, lobby_id) = match reader.read_u8()? {
        1 => (FragmentKind::Direct, None),
        2 => (FragmentKind::Lobby, None),
        3 => {
            let lobby_id = LobbyId(exact_array_from_vec(reader.read(32)?.to_vec())?);
            (FragmentKind::Lobby, Some(lobby_id))
        }
        _ => return Err(HydraMsgError::InvalidEncoding("fragment kind")),
    };
    let fragment_id = exact_array_from_vec(reader.read(32)?.to_vec())?;
    let total = reader.read_u32()? as usize;
    let index = reader.read_u32()? as usize;
    let len = reader.read_u32()? as usize;
    if len > hydra_core::FULL_MAX_CONTENT_SIZE {
        return Err(HydraMsgError::InvalidEncoding("fragment part size"));
    }
    let part = reader.read_vec(len)?;
    if !reader.is_finished() {
        return Err(HydraMsgError::InvalidEncoding("fragment trailing bytes"));
    }
    if total == 0 || total > MAX_FRAGMENTS_PER_MESSAGE || index >= total {
        return Err(HydraMsgError::InvalidEncoding("fragment part index"));
    }
    Ok(Some(FragmentRecord {
        kind,
        lobby_id,
        fragment_id,
        total,
        index,
        bytes: part,
    }))
}
