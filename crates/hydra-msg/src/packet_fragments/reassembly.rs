use super::records::{FragmentKind, FragmentRecord};
use crate::{
    limits::{
        MAX_FRAGMENTED_PAYLOAD_BYTES, MAX_FRAGMENT_AGE_SECS, MAX_INCOMPLETE_MESSAGES,
        MAX_INCOMPLETE_MESSAGES_PER_CONTACT, MAX_INCOMPLETE_MESSAGES_PER_LOBBY,
        MAX_PENDING_FRAGMENTS, MAX_PENDING_FRAGMENT_BYTES,
    },
    time::HydraInstant,
    ContactId, HydraMsgError, HydraResult, LobbyId,
};
use std::{
    collections::{hash_map::Entry, HashMap},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum FragmentScopeKey {
    Direct,
    Lobby(LobbyId),
    LegacyLobby,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PendingFragmentKey {
    from: ContactId,
    scope: FragmentScopeKey,
    kind: FragmentKind,
    fragment_id: [u8; 32],
}

impl PendingFragmentKey {
    pub(crate) const fn from(self) -> ContactId {
        self.from
    }

    pub(crate) const fn lobby_id(self) -> Option<LobbyId> {
        match self.scope {
            FragmentScopeKey::Lobby(lobby_id) => Some(lobby_id),
            FragmentScopeKey::Direct | FragmentScopeKey::LegacyLobby => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PendingInboundFragments {
    parts: HashMap<usize, Vec<u8>>,
    total: usize,
    received_bytes: usize,
    created_at: HydraInstant,
}

pub(super) struct ReassembledPayload {
    pub(super) bytes: Vec<u8>,
    pub(super) lobby_id: Option<LobbyId>,
}

pub(super) fn apply_fragment_record(
    pending_fragments: &mut HashMap<PendingFragmentKey, PendingInboundFragments>,
    from: ContactId,
    expected_kind: FragmentKind,
    part: FragmentRecord,
) -> HydraResult<Option<ReassembledPayload>> {
    if part.kind != expected_kind {
        return Err(HydraMsgError::InvalidEncoding("fragment kind"));
    }
    expire_stale_fragments(pending_fragments);
    let scope = match (part.kind, part.lobby_id) {
        (FragmentKind::Direct, None) => FragmentScopeKey::Direct,
        (FragmentKind::Lobby, Some(lobby_id)) => FragmentScopeKey::Lobby(lobby_id),
        (FragmentKind::Lobby, None) => FragmentScopeKey::LegacyLobby,
        (FragmentKind::Direct, Some(_)) => {
            return Err(HydraMsgError::InvalidEncoding("direct fragment scope"));
        }
    };
    let completed_lobby_id = part.lobby_id;
    let key = PendingFragmentKey {
        from,
        scope,
        kind: expected_kind,
        fragment_id: part.fragment_id,
    };

    if !pending_fragments.contains_key(&key) {
        reject_new_incomplete_message(pending_fragments, from, scope)?;
    }
    reject_global_fragment_budget(pending_fragments, &key, &part)?;

    let mut invalid = None;
    let complete = {
        let entry = match pending_fragments.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(PendingInboundFragments {
                parts: HashMap::new(),
                total: part.total,
                received_bytes: 0,
                created_at: HydraInstant::now(),
            }),
        };
        if entry.total != part.total {
            invalid = Some(HydraMsgError::InvalidEncoding("fragment part count"));
            false
        } else if let Some(existing) = entry.parts.get(&part.index) {
            if existing != &part.bytes {
                invalid = Some(HydraMsgError::InvalidEncoding(
                    "conflicting duplicate fragment",
                ));
            }
            entry.parts.len() == entry.total
        } else {
            match entry.received_bytes.checked_add(part.bytes.len()) {
                Some(total) if total <= MAX_FRAGMENTED_PAYLOAD_BYTES => {
                    entry.received_bytes = total;
                    entry.parts.insert(part.index, part.bytes);
                }
                _ => {
                    invalid = Some(HydraMsgError::InvalidEncoding("fragmented payload size"));
                }
            }
            entry.parts.len() == entry.total
        }
    };
    if let Some(error) = invalid {
        pending_fragments.remove(&key);
        return Err(error);
    }

    if !complete {
        return Ok(None);
    }
    let mut entry = pending_fragments
        .remove(&key)
        .ok_or(HydraMsgError::InvalidEncoding("fragment state"))?;
    let mut out = Vec::with_capacity(entry.received_bytes);
    for index in 0..entry.total {
        out.extend(
            entry
                .parts
                .remove(&index)
                .ok_or(HydraMsgError::InvalidEncoding("fragment part"))?,
        );
    }
    Ok(Some(ReassembledPayload {
        bytes: out,
        lobby_id: completed_lobby_id,
    }))
}

fn expire_stale_fragments(
    pending_fragments: &mut HashMap<PendingFragmentKey, PendingInboundFragments>,
) {
    let max_age = Duration::from_secs(MAX_FRAGMENT_AGE_SECS);
    pending_fragments.retain(|_, entry| entry.created_at.elapsed() <= max_age);
}

fn reject_new_incomplete_message(
    pending_fragments: &HashMap<PendingFragmentKey, PendingInboundFragments>,
    from: ContactId,
    scope: FragmentScopeKey,
) -> HydraResult<()> {
    if pending_fragments.len() >= MAX_INCOMPLETE_MESSAGES {
        return Err(HydraMsgError::InvalidInput(
            "too many incomplete fragmented messages",
        ));
    }
    let contact_count = pending_fragments
        .keys()
        .filter(|existing| existing.from == from)
        .count();
    let lobby_count = match scope {
        FragmentScopeKey::Lobby(lobby_id) => pending_fragments
            .keys()
            .filter(|existing| existing.lobby_id() == Some(lobby_id))
            .count(),
        FragmentScopeKey::Direct | FragmentScopeKey::LegacyLobby => 0,
    };
    if contact_count >= MAX_INCOMPLETE_MESSAGES_PER_CONTACT
        || lobby_count >= MAX_INCOMPLETE_MESSAGES_PER_LOBBY
    {
        return Err(HydraMsgError::InvalidInput(
            "too many incomplete messages for fragment scope",
        ));
    }
    Ok(())
}

fn reject_global_fragment_budget(
    pending_fragments: &HashMap<PendingFragmentKey, PendingInboundFragments>,
    key: &PendingFragmentKey,
    part: &FragmentRecord,
) -> HydraResult<()> {
    let already_present = pending_fragments
        .get(key)
        .is_some_and(|entry| entry.parts.contains_key(&part.index));
    if already_present {
        return Ok(());
    }
    let pending_parts = pending_fragments.values().fold(0usize, |total, entry| {
        total.saturating_add(entry.parts.len())
    });
    if pending_parts >= MAX_PENDING_FRAGMENTS {
        return Err(HydraMsgError::InvalidInput("too many pending fragments"));
    }
    let pending_bytes = pending_fragments.values().fold(0usize, |total, entry| {
        total.saturating_add(entry.received_bytes)
    });
    if pending_bytes
        .checked_add(part.bytes.len())
        .is_none_or(|total| total > MAX_PENDING_FRAGMENT_BYTES)
    {
        return Err(HydraMsgError::InvalidInput(
            "pending fragment byte budget exceeded",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
