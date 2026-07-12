use crate::{
    codec::*,
    limits::{reject_collection_growth, validate_label_input, MAX_LOBBIES},
    ContactId, Hydra, HydraMsgError, HydraResult,
};
use hydra_core::HASH_SIZE;
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

/// HYDRA lobby id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LobbyId(pub(crate) [u8; HASH_SIZE]);

impl LobbyId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: impl AsRef<str>) -> HydraResult<Self> {
        let hex = hex.as_ref();
        if hex.len() != HASH_SIZE * 2 {
            return Err(HydraMsgError::InvalidEncoding("lobby id size"));
        }
        Ok(Self(exact_array_from_vec(hex_decode(hex)?)?))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    #[must_use]
    pub fn hex(self) -> String {
        hex_encode(&self.0)
    }
}

/// Lobby creation policy.
///
/// The label is local state by default and is not exposed in minimized invites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobbyPolicy {
    pub max_members: usize,
    pub label: String,
}

impl HydraLobbyPolicy {
    #[must_use]
    pub fn new(label: impl Into<String>, max_members: usize) -> Self {
        Self {
            label: label.into(),
            max_members,
        }
    }
}

impl Default for HydraLobbyPolicy {
    fn default() -> Self {
        Self::new("", 64)
    }
}

/// Lobby summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobby {
    pub(crate) id: LobbyId,
    pub(crate) policy: HydraLobbyPolicy,
    pub(crate) members: Vec<ContactId>,
}

impl HydraLobby {
    #[must_use]
    pub const fn id(&self) -> LobbyId {
        self.id
    }

    #[must_use]
    pub const fn policy(&self) -> &HydraLobbyPolicy {
        &self.policy
    }

    #[must_use]
    pub fn members(&self) -> &[ContactId] {
        &self.members
    }
}

/// Opaque lobby invite bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraLobbyInvite(pub(crate) Vec<u8>);

impl HydraLobbyInvite {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HydraLobbyInvite {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Fresh one-time lobby invite output for unlinkable lobby setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraOneTimeLobbyInvite {
    pub(crate) lobby_id: LobbyId,
    pub(crate) invite: HydraLobbyInvite,
}

impl HydraOneTimeLobbyInvite {
    #[must_use]
    pub const fn lobby_id(&self) -> LobbyId {
        self.lobby_id
    }

    #[must_use]
    pub const fn invite(&self) -> &HydraLobbyInvite {
        &self.invite
    }

    #[must_use]
    pub fn into_invite(self) -> HydraLobbyInvite {
        self.invite
    }

    #[must_use]
    pub fn into_parts(self) -> (LobbyId, HydraLobbyInvite) {
        (self.lobby_id, self.invite)
    }
}

impl Hydra {
    pub fn create_lobby(&mut self, policy: HydraLobbyPolicy) -> HydraResult<HydraLobby> {
        validate_lobby_policy(&policy)?;
        validate_label_input(&policy.label, "lobby label size")?;
        reject_collection_growth(self.lobbies.len(), 1, MAX_LOBBIES, "lobby limit")?;
        let mut seed = Vec::new();
        seed.extend_from_slice(policy.label.as_bytes());
        seed.extend_from_slice(&random_array::<32>()?);
        let id = LobbyId(RustCryptoBackend::sha3_256(&seed));
        let lobby = HydraLobby {
            id,
            policy,
            members: Vec::new(),
        };
        self.lobbies.insert(id, lobby.clone());
        self.persist()?;
        Ok(lobby)
    }

    pub fn create_lobby_invite(&self, lobby_id: LobbyId) -> HydraResult<HydraLobbyInvite> {
        let lobby = self
            .lobbies
            .get(&lobby_id)
            .ok_or(HydraMsgError::LobbyNotFound)?;
        Ok(HydraLobbyInvite(encode_lobby_invite(lobby, false, None)))
    }

    pub fn create_labeled_lobby_invite(&self, lobby_id: LobbyId) -> HydraResult<HydraLobbyInvite> {
        let lobby = self
            .lobbies
            .get(&lobby_id)
            .ok_or(HydraMsgError::LobbyNotFound)?;
        Ok(HydraLobbyInvite(encode_lobby_invite(lobby, true, None)))
    }

    pub fn create_lobby_member_invite(&self, lobby_id: LobbyId) -> HydraResult<HydraLobbyInvite> {
        let lobby = self
            .lobbies
            .get(&lobby_id)
            .ok_or(HydraMsgError::LobbyNotFound)?;
        let members = self.lobby_invite_members(lobby);
        Ok(HydraLobbyInvite(encode_lobby_invite(
            lobby,
            true,
            Some(&members),
        )))
    }

    pub fn create_one_time_lobby_invite(
        &mut self,
        max_members: usize,
    ) -> HydraResult<HydraOneTimeLobbyInvite> {
        let lobby = self.create_lobby(HydraLobbyPolicy::new("", max_members))?;
        let invite = self.create_lobby_invite(lobby.id())?;
        Ok(HydraOneTimeLobbyInvite {
            lobby_id: lobby.id(),
            invite,
        })
    }

    pub fn preview_lobby_invite(&self, invite: impl AsRef<[u8]>) -> HydraResult<HydraLobby> {
        let mut lobby = decode_lobby_invite(invite.as_ref())?;
        validate_lobby_policy(&lobby.policy)?;
        validate_label_input(&lobby.policy.label, "lobby label size")?;
        self.normalize_lobby_members_for_local_identity(&mut lobby);
        Ok(lobby)
    }

    pub fn join_lobby(&mut self, invite: impl AsRef<[u8]>) -> HydraResult<HydraLobby> {
        let mut lobby = decode_lobby_invite(invite.as_ref())?;
        validate_lobby_policy(&lobby.policy)?;
        validate_label_input(&lobby.policy.label, "lobby label size")?;
        self.normalize_lobby_members_for_local_identity(&mut lobby);
        if !self.lobbies.contains_key(&lobby.id) {
            reject_collection_growth(self.lobbies.len(), 1, MAX_LOBBIES, "lobby limit")?;
        }
        self.lobbies.insert(lobby.id, lobby.clone());
        self.persist()?;
        Ok(lobby)
    }

    pub fn leave_lobby(&mut self, lobby_id: LobbyId) -> HydraResult<()> {
        self.lobbies
            .remove(&lobby_id)
            .ok_or(HydraMsgError::LobbyNotFound)?;
        self.pending_fragments
            .retain(|key, _| key.lobby_id() != Some(lobby_id));
        self.persist()?;
        Ok(())
    }

    #[must_use]
    pub fn list_lobbies(&self) -> Vec<HydraLobby> {
        self.lobbies.values().cloned().collect()
    }

    pub fn get_lobby(&self, lobby_id: LobbyId) -> HydraResult<HydraLobby> {
        self.lobbies
            .get(&lobby_id)
            .cloned()
            .ok_or(HydraMsgError::LobbyNotFound)
    }

    pub fn lobby_members(&self, lobby_id: LobbyId) -> HydraResult<Vec<ContactId>> {
        Ok(self.get_lobby(lobby_id)?.members)
    }

    pub fn add_lobby_member(
        &mut self,
        lobby_id: LobbyId,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        self.require_contact(contact_id)?;
        let mut changed = false;
        {
            let lobby = self
                .lobbies
                .get_mut(&lobby_id)
                .ok_or(HydraMsgError::LobbyNotFound)?;
            if !lobby.members.contains(&contact_id) {
                if lobby.members.len() >= lobby.policy.max_members {
                    return Err(HydraMsgError::InvalidInput("lobby member limit reached"));
                }
                lobby.members.push(contact_id);
                changed = true;
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    pub fn remove_lobby_member(
        &mut self,
        lobby_id: LobbyId,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        {
            let lobby = self
                .lobbies
                .get_mut(&lobby_id)
                .ok_or(HydraMsgError::LobbyNotFound)?;
            lobby.members.retain(|member| *member != contact_id);
        }
        self.persist()?;
        Ok(())
    }

    pub fn close_lobby(&mut self, lobby_id: LobbyId) -> HydraResult<()> {
        self.leave_lobby(lobby_id)
    }

    fn lobby_invite_members(&self, lobby: &HydraLobby) -> Vec<ContactId> {
        let mut members = Vec::new();
        if let Some(active_id) = self.active_id {
            members.push(ContactId(active_id.0));
        }
        for member in &lobby.members {
            if !members.contains(member) {
                members.push(*member);
            }
        }
        members
    }

    fn normalize_lobby_members_for_local_identity(&self, lobby: &mut HydraLobby) {
        let local_contact_id = self.active_id.map(|id| ContactId(id.0));
        let mut normalized = Vec::new();
        for member in &lobby.members {
            if Some(*member) == local_contact_id {
                continue;
            }
            if !normalized.contains(member) {
                normalized.push(*member);
            }
        }
        lobby.members = normalized;
    }
}
