//! WASM/JavaScript bindings for the simple `hydra-msg` facade.
//!
//! This crate intentionally mirrors the public Rust facade without exposing
//! protocol internals, suites, chunking, session export/import, or builders.
//! Browser persistence is explicit: `openPersistent` uses IndexedDB for opaque
//! encrypted snapshots, while `openEphemeral` is intentionally in-memory.

#![forbid(unsafe_code)]

use hydra_msg::{
    ContactId, HandshakeAnswer, HandshakeOffer, Hydra, HydraEnvelope, HydraLobbyPolicy,
    HydraMessage, IdentityId, LobbyId, MessageId,
};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

mod types;

pub use types::{
    WasmHydraBenchmarkReport, WasmHydraLobbyEnvelope, WasmHydraMessage, WasmReceivedHydraMessage,
};

#[wasm_bindgen]
pub struct WasmHydra {
    inner: Hydra,
    persistent_name: Option<String>,
    persistent_revision: Option<u64>,
    dirty: bool,
}

#[wasm_bindgen]
impl WasmHydra {
    #[wasm_bindgen(js_name = openEphemeral)]
    pub fn open_ephemeral(data_dir: &str, state_password: &str) -> Result<WasmHydra, JsValue> {
        Ok(Self {
            inner: Hydra::open(data_dir, state_password).map_err(to_js_error)?,
            persistent_name: None,
            persistent_revision: None,
            dirty: false,
        })
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = openPersistent)]
    pub async fn open_persistent(
        name: String,
        state_password: String,
    ) -> Result<WasmHydra, JsValue> {
        let (inner, revision) = Hydra::open_browser_persistent(&name, &state_password)
            .await
            .map_err(to_js_error)?;
        Ok(Self {
            inner,
            persistent_name: Some(name),
            persistent_revision: Some(revision),
            dirty: false,
        })
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = deletePersistent)]
    pub async fn delete_persistent(name: String) -> Result<(), JsValue> {
        Hydra::delete_browser_persistent(&name)
            .await
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = changeStatePassword)]
    pub fn change_state_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .change_state_password(old_password, new_password)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = browserLifecycleStatus)]
    pub async fn browser_lifecycle_status() -> Result<String, JsValue> {
        Hydra::browser_lifecycle_status().await.map_err(to_js_error)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = requestPersistentStorage)]
    pub async fn request_persistent_storage() -> Result<bool, JsValue> {
        Hydra::request_persistent_storage()
            .await
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = setPacketSize)]
    pub fn set_packet_size(&mut self, bytes: usize) -> Result<(), JsValue> {
        self.inner.set_packet_size(bytes).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = packetSize)]
    pub fn packet_size(&self) -> usize {
        self.inner.packet_size()
    }

    #[wasm_bindgen(js_name = isPersistent)]
    pub fn is_persistent(&self) -> bool {
        self.persistent_name.is_some()
    }

    #[wasm_bindgen(js_name = isDirty)]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    #[wasm_bindgen(js_name = persistentRevision)]
    pub fn persistent_revision(&self) -> Option<f64> {
        self.persistent_revision.map(|revision| revision as f64)
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = flush)]
    pub async fn flush(&mut self) -> Result<(), JsValue> {
        let Some(name) = self.persistent_name.clone() else {
            self.dirty = false;
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        let expected_revision = self.persistent_revision.unwrap_or(0);
        let new_revision = self
            .inner
            .flush_browser_persistent(&name, expected_revision)
            .await
            .map_err(to_js_error)?;
        self.persistent_revision = Some(new_revision);
        self.dirty = false;
        Ok(())
    }

    #[wasm_bindgen(js_name = generateId)]
    pub fn generate_id(&mut self, password: &str) -> Result<String, JsValue> {
        let id = self.inner.generate_id(password).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(id.hex())
    }

    #[wasm_bindgen(js_name = importId)]
    pub fn import_id(&mut self, bytes: Vec<u8>, password: &str) -> Result<String, JsValue> {
        let id = self.inner.import_id(bytes, password).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(id.hex())
    }

    #[wasm_bindgen(js_name = exportId)]
    pub fn export_id(&self, id_hex: &str, password: &str) -> Result<Vec<u8>, JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.export_id(id, password).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = listIds)]
    pub fn list_ids(&self) -> Array {
        self.inner
            .list_ids()
            .into_iter()
            .map(|summary| JsValue::from_str(&summary.id().hex()))
            .collect()
    }

    #[wasm_bindgen(js_name = getId)]
    pub fn get_id(&self, id_hex: &str) -> Result<String, JsValue> {
        let summary = self
            .inner
            .get_id(IdentityId::from_hex(id_hex).map_err(to_js_error)?)
            .map_err(to_js_error)?;
        Ok(format!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"unlocked\":{}}}",
            summary.id().hex(),
            escape_json(summary.label()),
            summary.unlocked()
        ))
    }

    #[wasm_bindgen(js_name = activeId)]
    pub fn active_id(&self) -> Option<String> {
        self.inner.active_id().map(|id| id.hex())
    }

    #[wasm_bindgen(js_name = setActiveId)]
    pub fn set_active_id(&mut self, id_hex: &str, password: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner
            .set_active_id(id, password)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = unlockId)]
    pub fn unlock_id(&mut self, id_hex: &str, password: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.unlock_id(id, password).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = lockId)]
    pub fn lock_id(&mut self, id_hex: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.lock_id(id).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = lockActiveId)]
    pub fn lock_active_id(&mut self) -> Result<(), JsValue> {
        self.inner.lock_active_id().map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = renameId)]
    pub fn rename_id(&mut self, id_hex: &str, label: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.rename_id(id, label).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = changeIdPassword)]
    pub fn change_id_password(
        &mut self,
        id_hex: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner
            .change_id_password(id, old_password, new_password)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = deleteId)]
    pub fn delete_id(&mut self, id_hex: &str, password: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.delete_id(id, password).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = createContactCard)]
    pub fn create_contact_card(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.create_contact_card().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = createLabeledContactCard)]
    pub fn create_labeled_contact_card(&self, label: &str) -> Result<Vec<u8>, JsValue> {
        self.inner
            .create_labeled_contact_card(label)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = createOneTimeContactCard)]
    pub fn create_one_time_contact_card(&mut self, password: &str) -> Result<String, JsValue> {
        let card = self
            .inner
            .create_one_time_contact_card(password)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(format!(
            "{{\"identityId\":\"{}\",\"cardHex\":\"{}\"}}",
            card.identity_id().hex(),
            hex_encode(card.card())
        ))
    }

    #[wasm_bindgen(js_name = previewContactCard)]
    pub fn preview_contact_card(&self, contact_card: Vec<u8>) -> Result<String, JsValue> {
        let contact = self
            .inner
            .preview_contact_card(contact_card)
            .map_err(to_js_error)?;
        Ok(format!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"safetyCode\":\"{}\"}}",
            contact.id().hex(),
            escape_json(contact.label()),
            contact.safety_code()
        ))
    }

    #[wasm_bindgen(js_name = createContactInvite)]
    pub fn create_contact_invite(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.create_contact_invite().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = addContact)]
    pub fn add_contact(&mut self, contact_card: Vec<u8>) -> Result<String, JsValue> {
        let contact = self.inner.add_contact(contact_card).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(contact.id().hex())
    }

    #[wasm_bindgen(js_name = importContacts)]
    pub fn import_contacts(&mut self, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.inner.import_contacts(bytes).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = exportContacts)]
    pub fn export_contacts(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_contacts().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = listContacts)]
    pub fn list_contacts(&self) -> Array {
        self.inner
            .list_contacts()
            .into_iter()
            .map(|contact| JsValue::from_str(&contact.id().hex()))
            .collect()
    }

    #[wasm_bindgen(js_name = getContact)]
    pub fn get_contact(&self, contact_id_hex: &str) -> Result<String, JsValue> {
        let contact = self
            .inner
            .get_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        Ok(format!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"verified\":{},\"blocked\":{},\"safetyCode\":\"{}\"}}",
            contact.id().hex(),
            escape_json(contact.label()),
            contact.verified(),
            contact.blocked(),
            contact.safety_code()
        ))
    }

    #[wasm_bindgen(js_name = contactSafetyCode)]
    pub fn contact_safety_code(&self, contact_id_hex: &str) -> Result<String, JsValue> {
        let id = contact_id(contact_id_hex)?;
        Ok(self
            .inner
            .get_contact(id)
            .map_err(to_js_error)?
            .safety_code())
    }

    #[wasm_bindgen(js_name = verifyContact)]
    pub fn verify_contact(
        &mut self,
        contact_id_hex: &str,
        safety_code: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .verify_contact(contact_id(contact_id_hex)?, safety_code)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = unverifyContact)]
    pub fn unverify_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .unverify_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = renameContact)]
    pub fn rename_contact(&mut self, contact_id_hex: &str, label: &str) -> Result<(), JsValue> {
        self.inner
            .rename_contact(contact_id(contact_id_hex)?, label)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = removeContact)]
    pub fn remove_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .remove_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = blockContact)]
    pub fn block_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .block_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = unblockContact)]
    pub fn unblock_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .unblock_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = initHandshake)]
    pub fn init_handshake(&mut self, contact_id_hex: &str) -> Result<Vec<u8>, JsValue> {
        let offer = self
            .inner
            .init_handshake(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(offer.into_bytes())
    }

    #[wasm_bindgen(js_name = replyHandshake)]
    pub fn reply_handshake(&mut self, offer: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        let answer = self
            .inner
            .reply_handshake(HandshakeOffer::from_bytes(offer))
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(answer.into_bytes())
    }

    #[wasm_bindgen(js_name = finishHandshake)]
    pub fn finish_handshake(&mut self, answer: Vec<u8>) -> Result<(), JsValue> {
        self.inner
            .finish_handshake(HandshakeAnswer::from_bytes(answer))
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = sessionStatus)]
    pub fn session_status(&self, contact_id_hex: &str) -> Result<String, JsValue> {
        Ok(format!(
            "{:?}",
            self.inner
                .session_status(contact_id(contact_id_hex)?)
                .map_err(to_js_error)?
        ))
    }

    #[wasm_bindgen(js_name = rekeySession)]
    pub fn rekey_session(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .rekey_session(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = closeSession)]
    pub fn close_session(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .close_session(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = send)]
    pub fn send(
        &mut self,
        contact_id_hex: &str,
        message: &WasmHydraMessage,
    ) -> Result<Array, JsValue> {
        let packets = self
            .inner
            .send(contact_id(contact_id_hex)?, message.inner.clone())
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(packet_array(packets))
    }

    #[wasm_bindgen(js_name = sendText)]
    pub fn send_text(&mut self, contact_id_hex: &str, text: &str) -> Result<Array, JsValue> {
        let packets = self
            .inner
            .send(contact_id(contact_id_hex)?, HydraMessage::text(text))
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(packet_array(packets))
    }

    #[wasm_bindgen(js_name = receive)]
    pub fn receive(&mut self, envelope: Vec<u8>) -> Result<JsValue, JsValue> {
        let Some(inner) = self
            .inner
            .receive(HydraEnvelope::from_bytes(envelope))
            .map_err(to_js_error)?
        else {
            self.mark_dirty();
            return Ok(JsValue::NULL);
        };
        self.mark_dirty();
        Ok(WasmReceivedHydraMessage { inner }.into())
    }

    #[wasm_bindgen(js_name = listMessages)]
    pub fn list_messages(&self, contact_id_hex: &str) -> Result<Array, JsValue> {
        Ok(self
            .inner
            .list_messages(contact_id(contact_id_hex)?)
            .into_iter()
            .map(|id| JsValue::from_f64(id.value() as f64))
            .collect())
    }

    #[wasm_bindgen(js_name = getMessage)]
    pub fn get_message(&self, message_id: u64) -> Result<WasmReceivedHydraMessage, JsValue> {
        Ok(WasmReceivedHydraMessage {
            inner: self
                .inner
                .get_message(MessageId::from_u64(message_id))
                .map_err(to_js_error)?,
        })
    }

    #[wasm_bindgen(js_name = deleteMessage)]
    pub fn delete_message(&mut self, message_id: u64) -> Result<(), JsValue> {
        self.inner
            .delete_message(MessageId::from_u64(message_id))
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = clearMessages)]
    pub fn clear_messages(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .clear_messages(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = exportMessages)]
    pub fn export_messages(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_messages().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = importMessages)]
    pub fn import_messages(&mut self, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.inner.import_messages(bytes).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = createLobby)]
    pub fn create_lobby(&mut self, label: &str, max_members: usize) -> Result<String, JsValue> {
        let lobby = self
            .inner
            .create_lobby(HydraLobbyPolicy::new(label, max_members))
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(lobby.id().hex())
    }

    #[wasm_bindgen(js_name = createLobbyInvite)]
    pub fn create_lobby_invite(&self, lobby_id_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .create_lobby_invite(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = createLabeledLobbyInvite)]
    pub fn create_labeled_lobby_invite(&self, lobby_id_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .create_labeled_lobby_invite(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = createLobbyMemberInvite)]
    pub fn create_lobby_member_invite(&self, lobby_id_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .create_lobby_member_invite(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = createOneTimeLobbyInvite)]
    pub fn create_one_time_lobby_invite(&mut self, max_members: usize) -> Result<String, JsValue> {
        let invite = self
            .inner
            .create_one_time_lobby_invite(max_members)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(format!(
            "{{\"lobbyId\":\"{}\",\"inviteHex\":\"{}\"}}",
            invite.lobby_id().hex(),
            hex_encode(invite.invite().as_bytes())
        ))
    }

    #[wasm_bindgen(js_name = previewLobbyInvite)]
    pub fn preview_lobby_invite(&self, invite: Vec<u8>) -> Result<String, JsValue> {
        let lobby = self
            .inner
            .preview_lobby_invite(invite)
            .map_err(to_js_error)?;
        Ok(format!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"maxMembers\":{},\"memberCount\":{}}}",
            lobby.id().hex(),
            escape_json(&lobby.policy().label),
            lobby.policy().max_members,
            lobby.members().len()
        ))
    }

    #[wasm_bindgen(js_name = joinLobby)]
    pub fn join_lobby(&mut self, invite: Vec<u8>) -> Result<String, JsValue> {
        let lobby = self.inner.join_lobby(invite).map_err(to_js_error)?;
        self.mark_dirty();
        Ok(lobby.id().hex())
    }

    #[wasm_bindgen(js_name = leaveLobby)]
    pub fn leave_lobby(&mut self, lobby_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .leave_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = listLobbies)]
    pub fn list_lobbies(&self) -> Array {
        self.inner
            .list_lobbies()
            .into_iter()
            .map(|lobby| JsValue::from_str(&lobby.id().hex()))
            .collect()
    }

    #[wasm_bindgen(js_name = getLobby)]
    pub fn get_lobby(&self, lobby_id_hex: &str) -> Result<String, JsValue> {
        let lobby = self
            .inner
            .get_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?;
        Ok(format!(
            "{{\"id\":\"{}\",\"label\":\"{}\",\"maxMembers\":{},\"memberCount\":{}}}",
            lobby.id().hex(),
            escape_json(&lobby.policy().label),
            lobby.policy().max_members,
            lobby.members().len()
        ))
    }

    #[wasm_bindgen(js_name = lobbyMembers)]
    pub fn lobby_members(&self, lobby_id_hex: &str) -> Result<Array, JsValue> {
        Ok(self
            .inner
            .lobby_members(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?
            .into_iter()
            .map(|member| JsValue::from_str(&member.hex()))
            .collect())
    }

    #[wasm_bindgen(js_name = addLobbyMember)]
    pub fn add_lobby_member(
        &mut self,
        lobby_id_hex: &str,
        contact_id_hex: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .add_lobby_member(lobby_id(lobby_id_hex)?, contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = removeLobbyMember)]
    pub fn remove_lobby_member(
        &mut self,
        lobby_id_hex: &str,
        contact_id_hex: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .remove_lobby_member(lobby_id(lobby_id_hex)?, contact_id(contact_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = sendLobby)]
    pub fn send_lobby(
        &mut self,
        lobby_id_hex: &str,
        message: &WasmHydraMessage,
    ) -> Result<Array, JsValue> {
        let envelopes = self
            .inner
            .send_lobby(lobby_id(lobby_id_hex)?, message.inner.clone())
            .map_err(to_js_error)?;
        let array = Array::new();
        for inner in envelopes {
            let value: JsValue = WasmHydraLobbyEnvelope { inner }.into();
            array.push(&value);
        }
        self.mark_dirty();
        Ok(array)
    }

    #[wasm_bindgen(js_name = receiveLobby)]
    pub fn receive_lobby(&mut self, envelope: Vec<u8>) -> Result<JsValue, JsValue> {
        let Some(inner) = self
            .inner
            .receive_lobby(HydraEnvelope::from_bytes(envelope))
            .map_err(to_js_error)?
        else {
            self.mark_dirty();
            return Ok(JsValue::NULL);
        };
        self.mark_dirty();
        Ok(WasmReceivedHydraMessage { inner }.into())
    }

    #[wasm_bindgen(js_name = rekeyLobby)]
    pub fn rekey_lobby(&mut self, lobby_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .rekey_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = closeLobby)]
    pub fn close_lobby(&mut self, lobby_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .close_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = exportBackup)]
    pub fn export_backup(&self, password: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.export_backup(password).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = importBackup)]
    pub fn import_backup(&mut self, bytes: Vec<u8>, password: &str) -> Result<(), JsValue> {
        self.inner
            .import_backup(bytes, password)
            .map_err(to_js_error)?;
        self.mark_dirty();
        Ok(())
    }

    #[wasm_bindgen(js_name = verifyBackup)]
    pub fn verify_backup(&self, bytes: Vec<u8>, password: &str) -> Result<(), JsValue> {
        self.inner
            .verify_backup(bytes, password)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = storageStatus)]
    pub fn storage_status(&self) -> String {
        let status = self.inner.storage_status();
        let persistent_revision = self
            .persistent_revision
            .map(|revision| revision.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"dataDir\":\"{}\",\"encryptedState\":{},\"persistent\":{},\"persistentRevision\":{},\"dirty\":{}}}",
            status.data_dir.display(),
            status.encrypted_state,
            self.is_persistent(),
            persistent_revision,
            self.is_dirty(),
        )
    }

    #[wasm_bindgen(js_name = storageDebugStatus)]
    pub fn storage_debug_status(&self) -> String {
        let status = self.inner.storage_debug_status();
        let persistent_revision = self
            .persistent_revision
            .map(|revision| revision.to_string())
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"dataDir\":\"{}\",\"identityCount\":{},\"contactCount\":{},\"sessionCount\":{},\"messageCount\":{},\"lobbyCount\":{},\"stateGeneration\":{},\"encryptedState\":{},\"persistent\":{},\"persistentRevision\":{},\"dirty\":{},\"debug\":true}}",
            status.data_dir.display(),
            status.identity_count,
            status.contact_count,
            status.session_count,
            status.message_count,
            status.lobby_count,
            status.state_generation,
            status.encrypted_state,
            self.is_persistent(),
            persistent_revision,
            self.is_dirty(),
        )
    }

    #[wasm_bindgen(js_name = benchmark)]
    pub fn benchmark(&self) -> Result<WasmHydraBenchmarkReport, JsValue> {
        Ok(WasmHydraBenchmarkReport {
            inner: self.inner.benchmark().map_err(to_js_error)?,
        })
    }
}

impl WasmHydra {
    fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

fn packet_array(packets: Vec<HydraEnvelope>) -> Array {
    let array = Array::new();
    for packet in packets {
        array.push(&Uint8Array::from(packet.as_bytes()));
    }
    array
}

fn contact_id(hex: &str) -> Result<ContactId, JsValue> {
    ContactId::from_hex(hex).map_err(to_js_error)
}

fn lobby_id(hex: &str) -> Result<LobbyId, JsValue> {
    LobbyId::from_hex(hex).map_err(to_js_error)
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn to_js_error(error: impl ToString) -> JsValue {
    JsValue::from_str(&error.to_string())
}
