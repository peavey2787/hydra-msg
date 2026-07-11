use crate::{
    AppUiState, CarrierConfig, ContactId, ConversationRef, DisplayDirection, DisplayMessage,
    HydraContact, HydraIdentitySummary, HydraLobby, HydraLobbyPolicy, HydraLobbyRoutingHint,
    HydraMessage, HydraOneTimeContactCard, HydraResult, HydraSessionStatus,
    HydraStorageDebugStatus, HydraStorageStatus, IdentityId, LobbyId, NotificationPreferences,
    ReceivedHydraMessage, RememberMePolicy,
};
use hydra_msg::{Hydra, HydraEnvelope};
use std::path::Path;

const MAX_IDENTITY_LABEL_BYTES: usize = 256;

/// Opaque lobby packet plus app-local routing metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedLobbyPacket {
    pub recipient: ContactId,
    pub routing_hint: HydraLobbyRoutingHint,
    pub bytes: Vec<u8>,
}

/// Production reference-app state coordinator.
///
/// Every security-sensitive operation delegates directly to the public
/// `hydra-msg` facade. The remaining state is transient UX metadata.
pub struct HydraApp {
    hydra: Hydra,
    ui: AppUiState,
}

impl HydraApp {
    /// Opens or creates the encrypted SDK profile.
    pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>) -> HydraResult<Self> {
        Ok(Self {
            hydra: Hydra::open(data_dir, state_password)?,
            ui: AppUiState::default(),
        })
    }

    #[must_use]
    pub const fn active_identity(&self) -> Option<IdentityId> {
        self.hydra.active_id()
    }

    #[must_use]
    pub const fn ui(&self) -> &AppUiState {
        &self.ui
    }

    pub fn set_carrier_config(&mut self, config: CarrierConfig) {
        self.ui.carrier = config;
    }

    pub fn set_notification_preferences(&mut self, preferences: NotificationPreferences) {
        self.ui.notifications = preferences;
    }

    pub fn select_conversation(
        &mut self,
        conversation: Option<ConversationRef>,
    ) -> HydraResult<()> {
        if let Some(conversation) = conversation {
            self.validate_conversation(conversation)?;
        }
        self.ui.selected_conversation = conversation;
        Ok(())
    }

    pub fn set_draft(
        &mut self,
        conversation: ConversationRef,
        draft: impl Into<String>,
    ) -> HydraResult<()> {
        self.validate_conversation(conversation)?;
        let _ = self.ui.drafts.insert(conversation, draft.into());
        Ok(())
    }

    pub fn take_draft(&mut self, conversation: ConversationRef) -> Option<String> {
        self.ui.drafts.remove(&conversation)
    }

    pub fn set_remember_me(
        &mut self,
        id: IdentityId,
        policy: RememberMePolicy,
    ) -> HydraResult<()> {
        self.hydra.get_id(id)?;
        if policy == RememberMePolicy::Never {
            let _ = self.ui.remember_me.remove(&id);
        } else {
            let _ = self.ui.remember_me.insert(id, policy);
        }
        Ok(())
    }

    #[must_use]
    pub fn remember_me(&self, id: IdentityId) -> RememberMePolicy {
        self.ui.remember_me.get(&id).copied().unwrap_or_default()
    }

    pub fn set_contact_alias(
        &mut self,
        contact_id: ContactId,
        alias: impl Into<String>,
    ) -> HydraResult<()> {
        self.hydra.get_contact(contact_id)?;
        let _ = self.ui.contact_aliases.insert(contact_id, alias.into());
        Ok(())
    }

    #[must_use]
    pub fn contact_alias(&self, contact_id: ContactId) -> Option<&str> {
        self.ui.contact_aliases.get(&contact_id).map(String::as_str)
    }

    pub fn generate_identity(
        &mut self,
        label: impl Into<String>,
        identity_password: impl AsRef<str>,
    ) -> HydraResult<IdentityId> {
        let identity_password = identity_password.as_ref();
        let label = label.into();
        validate_identity_label(&label)?;
        let id = self.hydra.generate_id(identity_password)?;
        if let Err(error) = self.hydra.rename_id(id, label) {
            let _ = self.hydra.delete_id(id, identity_password);
            return Err(error);
        }
        if let Err(error) = self.hydra.set_active_id(id, identity_password) {
            let _ = self.hydra.delete_id(id, identity_password);
            return Err(error);
        }
        self.ui.selected_profile = Some(id);
        Ok(id)
    }

    #[must_use]
    pub fn list_identities(&self) -> Vec<HydraIdentitySummary> {
        self.hydra.list_ids()
    }

    pub fn switch_identity(
        &mut self,
        id: IdentityId,
        identity_password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.set_active_id(id, identity_password)?;
        self.ui.selected_profile = Some(id);
        Ok(())
    }

    pub fn unlock_identity(
        &mut self,
        id: IdentityId,
        identity_password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.unlock_id(id, identity_password)
    }

    pub fn lock_identity(&mut self, id: IdentityId) -> HydraResult<()> {
        self.hydra.lock_id(id)?;
        let _ = self.ui.remember_me.remove(&id);
        if self.ui.selected_profile == Some(id) {
            self.ui.selected_profile = None;
        }
        Ok(())
    }

    pub fn lock_active_identity(&mut self) -> HydraResult<()> {
        let active = self.hydra.active_id();
        self.hydra.lock_active_id()?;
        if let Some(id) = active {
            let _ = self.ui.remember_me.remove(&id);
        }
        if self.ui.selected_profile == active {
            self.ui.selected_profile = None;
        }
        Ok(())
    }

    pub fn export_identity(
        &self,
        id: IdentityId,
        identity_password: impl AsRef<str>,
    ) -> HydraResult<Vec<u8>> {
        self.hydra.export_id(id, identity_password)
    }

    pub fn import_identity(
        &mut self,
        bytes: impl AsRef<[u8]>,
        identity_password: impl AsRef<str>,
        label: impl Into<String>,
    ) -> HydraResult<IdentityId> {
        let identity_password = identity_password.as_ref();
        let label = label.into();
        validate_identity_label(&label)?;
        let id = self.hydra.import_id(bytes, identity_password)?;
        if let Err(error) = self.hydra.rename_id(id, label) {
            let _ = self.hydra.delete_id(id, identity_password);
            return Err(error);
        }
        Ok(id)
    }

    pub fn change_identity_password(
        &mut self,
        id: IdentityId,
        old_password: impl AsRef<str>,
        new_password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra
            .change_id_password(id, old_password, new_password)
    }

    pub fn delete_identity(
        &mut self,
        id: IdentityId,
        identity_password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.delete_id(id, identity_password)?;
        let _ = self.ui.remember_me.remove(&id);
        if self.ui.selected_profile == Some(id) {
            self.ui.selected_profile = None;
        }
        Ok(())
    }

    pub fn create_contact_card(&self) -> HydraResult<Vec<u8>> {
        self.hydra.create_contact_card()
    }

    pub fn create_labeled_contact_card(&self, label: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        self.hydra.create_labeled_contact_card(label)
    }

    pub fn create_one_time_contact_card(
        &mut self,
        identity_password: impl AsRef<str>,
    ) -> HydraResult<HydraOneTimeContactCard> {
        let card = self
            .hydra
            .create_one_time_contact_card(identity_password)?;
        self.ui.selected_profile = Some(card.identity_id());
        Ok(card)
    }

    pub fn preview_contact_card(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> HydraResult<HydraContact> {
        self.hydra.preview_contact_card(bytes)
    }

    pub fn add_contact(&mut self, bytes: impl AsRef<[u8]>) -> HydraResult<HydraContact> {
        self.hydra.add_contact(bytes)
    }

    #[must_use]
    pub fn list_contacts(&self) -> Vec<HydraContact> {
        self.hydra.list_contacts()
    }

    pub fn verify_contact(
        &mut self,
        contact_id: ContactId,
        safety_code: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.verify_contact(contact_id, safety_code)
    }

    pub fn remove_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        self.hydra.remove_contact(contact_id)?;
        let _ = self.ui.contact_aliases.remove(&contact_id);
        let _ = self
            .ui
            .drafts
            .remove(&ConversationRef::Direct(contact_id));
        if self.ui.selected_conversation == Some(ConversationRef::Direct(contact_id)) {
            self.ui.selected_conversation = None;
        }
        Ok(())
    }

    pub fn export_contacts(&self) -> HydraResult<Vec<u8>> {
        self.hydra.export_contacts()
    }

    pub fn import_contacts(&mut self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        self.hydra.import_contacts(bytes)
    }

    pub fn handshake_offer(&mut self, contact_id: ContactId) -> HydraResult<Vec<u8>> {
        Ok(self.hydra.init_handshake(contact_id)?.into_bytes())
    }

    pub fn handshake_answer(&mut self, offer: impl AsRef<[u8]>) -> HydraResult<Vec<u8>> {
        Ok(self.hydra.reply_handshake(offer)?.into_bytes())
    }

    pub fn finish_handshake(&mut self, answer: impl AsRef<[u8]>) -> HydraResult<()> {
        self.hydra.finish_handshake(answer)
    }

    pub fn session_status(&self, contact_id: ContactId) -> HydraResult<HydraSessionStatus> {
        self.hydra.session_status(contact_id)
    }

    pub fn send_message(
        &mut self,
        contact_id: ContactId,
        message: impl Into<HydraMessage>,
    ) -> HydraResult<Vec<Vec<u8>>> {
        let message = message.into();
        let plaintext = message.plaintext().to_vec();
        let attachment_count = message.attachments().len();
        let packets = self
            .hydra
            .send(contact_id, message)?
            .into_iter()
            .map(HydraEnvelope::into_bytes)
            .collect();
        let message_id = self.hydra.list_messages(contact_id).last().copied();
        self.ui.display_history.push(DisplayMessage {
            conversation: ConversationRef::Direct(contact_id),
            direction: DisplayDirection::Sent,
            message_id,
            plaintext,
            attachment_count,
        });
        Ok(packets)
    }

    pub fn stored_messages(
        &self,
        contact_id: ContactId,
    ) -> HydraResult<Vec<ReceivedHydraMessage>> {
        self.hydra
            .list_messages(contact_id)
            .into_iter()
            .map(|message_id| self.hydra.get_message(message_id))
            .collect()
    }

    pub fn receive_message(
        &mut self,
        packet: impl AsRef<[u8]>,
    ) -> HydraResult<Option<ReceivedHydraMessage>> {
        let received = self.hydra.receive(packet)?;
        if let Some(message) = &received {
            self.ui.display_history.push(received_display_message(
                ConversationRef::Direct(message.from()),
                message,
            ));
        }
        Ok(received)
    }

    pub fn create_lobby(&mut self, policy: HydraLobbyPolicy) -> HydraResult<HydraLobby> {
        self.hydra.create_lobby(policy)
    }

    pub fn add_lobby_member(
        &mut self,
        lobby_id: LobbyId,
        contact_id: ContactId,
    ) -> HydraResult<()> {
        self.hydra.add_lobby_member(lobby_id, contact_id)
    }

    pub fn create_lobby_invite(&self, lobby_id: LobbyId) -> HydraResult<Vec<u8>> {
        Ok(self.hydra.create_lobby_invite(lobby_id)?.into_bytes())
    }

    pub fn join_lobby(&mut self, invite: impl AsRef<[u8]>) -> HydraResult<HydraLobby> {
        self.hydra.join_lobby(invite)
    }

    #[must_use]
    pub fn list_lobbies(&self) -> Vec<HydraLobby> {
        self.hydra.list_lobbies()
    }

    pub fn leave_lobby(&mut self, lobby_id: LobbyId) -> HydraResult<()> {
        self.hydra.leave_lobby(lobby_id)?;
        let _ = self.ui.drafts.remove(&ConversationRef::Lobby(lobby_id));
        if self.ui.selected_conversation == Some(ConversationRef::Lobby(lobby_id)) {
            self.ui.selected_conversation = None;
        }
        Ok(())
    }

    pub fn send_lobby_message(
        &mut self,
        lobby_id: LobbyId,
        message: impl Into<HydraMessage>,
    ) -> HydraResult<Vec<RoutedLobbyPacket>> {
        let message = message.into();
        let display = display_message(
            ConversationRef::Lobby(lobby_id),
            DisplayDirection::Sent,
            None,
            &message,
        );
        let packets = self
            .hydra
            .send_lobby(lobby_id, message)?
            .into_iter()
            .map(|packet| {
                let (recipient, routing_hint, envelope) = packet.into_routed_parts();
                RoutedLobbyPacket {
                    recipient,
                    routing_hint,
                    bytes: envelope.into_bytes(),
                }
            })
            .collect();
        self.ui.display_history.push(display);
        Ok(packets)
    }

    pub fn receive_lobby_message(
        &mut self,
        packet: impl AsRef<[u8]>,
    ) -> HydraResult<Option<ReceivedHydraMessage>> {
        let received = self.hydra.receive_lobby(packet)?;
        if let Some(message) = &received {
            if let Some(lobby_id) = message.lobby_id() {
                self.ui.display_history.push(received_display_message(
                    ConversationRef::Lobby(lobby_id),
                    message,
                ));
            }
        }
        Ok(received)
    }

    pub fn export_backup(&self, password: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        self.hydra.export_backup(password)
    }

    pub fn verify_backup(
        &self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.verify_backup(bytes, password)
    }

    pub fn import_backup(
        &mut self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.import_backup(bytes, password)?;
        self.ui = AppUiState::default();
        Ok(())
    }

    pub fn change_state_password(
        &mut self,
        old_password: impl AsRef<str>,
        new_password: impl AsRef<str>,
    ) -> HydraResult<()> {
        self.hydra.change_state_password(old_password, new_password)
    }

    #[must_use]
    pub fn storage_status(&self) -> HydraStorageStatus {
        self.hydra.storage_status()
    }

    #[must_use]
    pub fn storage_debug_status(&self) -> HydraStorageDebugStatus {
        self.hydra.storage_debug_status()
    }

    fn validate_conversation(&self, conversation: ConversationRef) -> HydraResult<()> {
        match conversation {
            ConversationRef::Direct(contact_id) => {
                self.hydra.get_contact(contact_id)?;
            }
            ConversationRef::Lobby(lobby_id) => {
                self.hydra.get_lobby(lobby_id)?;
            }
        }
        Ok(())
    }
}

fn display_message(
    conversation: ConversationRef,
    direction: DisplayDirection,
    message_id: Option<crate::MessageId>,
    message: &HydraMessage,
) -> DisplayMessage {
    DisplayMessage {
        conversation,
        direction,
        message_id,
        plaintext: message.plaintext().to_vec(),
        attachment_count: message.attachments().len(),
    }
}

fn received_display_message(
    conversation: ConversationRef,
    message: &ReceivedHydraMessage,
) -> DisplayMessage {
    DisplayMessage {
        conversation,
        direction: DisplayDirection::Received,
        message_id: Some(message.message_id()),
        plaintext: message.plaintext().to_vec(),
        attachment_count: message.attachments().len(),
    }
}


fn validate_identity_label(label: &str) -> HydraResult<()> {
    if label.len() > MAX_IDENTITY_LABEL_BYTES {
        return Err(crate::HydraMsgError::InvalidInput("identity label size"));
    }
    Ok(())
}
