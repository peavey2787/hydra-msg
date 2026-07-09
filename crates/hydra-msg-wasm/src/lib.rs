//! WASM/JavaScript bindings for the simple `hydra-msg` facade.
//!
//! This crate intentionally mirrors the public Rust facade without exposing
//! protocol internals, suites, chunking, session export/import, or builders.
//! Browser storage is in-memory for this phase; apps can persist by calling
//! `export_backup` / `import_backup` or the individual export/import helpers.

#![forbid(unsafe_code)]

use hydra_msg::{
    ContactId, HandshakeAnswer, HandshakeOffer, Hydra, HydraBenchmarkReport, HydraEnvelope,
    HydraLobbyEnvelope, HydraLobbyPolicy, HydraMessage, IdentityId, LobbyId, MessageId,
    ReceivedHydraMessage,
};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmHydra {
    inner: Hydra,
}

#[wasm_bindgen]
pub struct WasmHydraMessage {
    inner: HydraMessage,
}

#[wasm_bindgen]
pub struct WasmReceivedHydraMessage {
    inner: ReceivedHydraMessage,
}

#[wasm_bindgen]
pub struct WasmHydraLobbyEnvelope {
    inner: HydraLobbyEnvelope,
}

#[wasm_bindgen]
pub struct WasmHydraBenchmarkReport {
    inner: HydraBenchmarkReport,
}

#[wasm_bindgen]
impl WasmHydra {
    #[wasm_bindgen(js_name = open)]
    pub fn open(data_dir: &str, state_password: &str) -> Result<WasmHydra, JsValue> {
        Ok(Self {
            inner: Hydra::open(data_dir, state_password).map_err(to_js_error)?,
        })
    }

    #[wasm_bindgen(js_name = openDefault)]
    pub fn open_default(state_password: &str) -> Result<WasmHydra, JsValue> {
        Ok(Self {
            inner: Hydra::open_default(state_password).map_err(to_js_error)?,
        })
    }

    #[wasm_bindgen(js_name = generateId)]
    pub fn generate_id(&mut self, password: &str) -> Result<String, JsValue> {
        Ok(self.inner.generate_id(password).map_err(to_js_error)?.hex())
    }

    #[wasm_bindgen(js_name = importId)]
    pub fn import_id(&mut self, bytes: Vec<u8>, password: &str) -> Result<String, JsValue> {
        Ok(self
            .inner
            .import_id(bytes, password)
            .map_err(to_js_error)?
            .hex())
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
        self.inner.set_active_id(id, password).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = unlockId)]
    pub fn unlock_id(&mut self, id_hex: &str, password: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.unlock_id(id, password).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = lockId)]
    pub fn lock_id(&mut self, id_hex: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.lock_id(id).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = lockActiveId)]
    pub fn lock_active_id(&mut self) -> Result<(), JsValue> {
        self.inner.lock_active_id().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = renameId)]
    pub fn rename_id(&mut self, id_hex: &str, label: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.rename_id(id, label).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = deleteId)]
    pub fn delete_id(&mut self, id_hex: &str, password: &str) -> Result<(), JsValue> {
        let id = IdentityId::from_hex(id_hex).map_err(to_js_error)?;
        self.inner.delete_id(id, password).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = createContactCard)]
    pub fn create_contact_card(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.create_contact_card().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = createContactInvite)]
    pub fn create_contact_invite(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.create_contact_invite().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = addContact)]
    pub fn add_contact(&mut self, contact_card: Vec<u8>) -> Result<String, JsValue> {
        Ok(self
            .inner
            .add_contact(contact_card)
            .map_err(to_js_error)?
            .id()
            .hex())
    }

    #[wasm_bindgen(js_name = importContacts)]
    pub fn import_contacts(&mut self, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.inner.import_contacts(bytes).map_err(to_js_error)
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
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = unverifyContact)]
    pub fn unverify_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .unverify_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = renameContact)]
    pub fn rename_contact(&mut self, contact_id_hex: &str, label: &str) -> Result<(), JsValue> {
        self.inner
            .rename_contact(contact_id(contact_id_hex)?, label)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = removeContact)]
    pub fn remove_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .remove_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = blockContact)]
    pub fn block_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .block_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = unblockContact)]
    pub fn unblock_contact(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .unblock_contact(contact_id(contact_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = initHandshake)]
    pub fn init_handshake(&mut self, contact_id_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .init_handshake(contact_id(contact_id_hex)?)
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = replyHandshake)]
    pub fn reply_handshake(&mut self, offer: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .reply_handshake(HandshakeOffer::from_bytes(offer))
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = finishHandshake)]
    pub fn finish_handshake(&mut self, answer: Vec<u8>) -> Result<(), JsValue> {
        self.inner
            .finish_handshake(HandshakeAnswer::from_bytes(answer))
            .map_err(to_js_error)
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
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = closeSession)]
    pub fn close_session(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .close_session(contact_id(contact_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = send)]
    pub fn send(
        &mut self,
        contact_id_hex: &str,
        message: &WasmHydraMessage,
    ) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .send(contact_id(contact_id_hex)?, message.inner.clone())
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = sendText)]
    pub fn send_text(&mut self, contact_id_hex: &str, text: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .send(contact_id(contact_id_hex)?, HydraMessage::text(text))
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = receive)]
    pub fn receive(&mut self, envelope: Vec<u8>) -> Result<WasmReceivedHydraMessage, JsValue> {
        Ok(WasmReceivedHydraMessage {
            inner: self
                .inner
                .receive(HydraEnvelope::from_bytes(envelope))
                .map_err(to_js_error)?,
        })
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
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = clearMessages)]
    pub fn clear_messages(&mut self, contact_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .clear_messages(contact_id(contact_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = exportMessages)]
    pub fn export_messages(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_messages().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = importMessages)]
    pub fn import_messages(&mut self, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.inner.import_messages(bytes).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = createLobby)]
    pub fn create_lobby(&mut self, label: &str, max_members: usize) -> Result<String, JsValue> {
        Ok(self
            .inner
            .create_lobby(HydraLobbyPolicy::new(label, max_members))
            .map_err(to_js_error)?
            .id()
            .hex())
    }

    #[wasm_bindgen(js_name = createLobbyInvite)]
    pub fn create_lobby_invite(&self, lobby_id_hex: &str) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .create_lobby_invite(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)?
            .into_bytes())
    }

    #[wasm_bindgen(js_name = joinLobby)]
    pub fn join_lobby(&mut self, invite: Vec<u8>) -> Result<String, JsValue> {
        Ok(self
            .inner
            .join_lobby(invite)
            .map_err(to_js_error)?
            .id()
            .hex())
    }

    #[wasm_bindgen(js_name = leaveLobby)]
    pub fn leave_lobby(&mut self, lobby_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .leave_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)
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
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = removeLobbyMember)]
    pub fn remove_lobby_member(
        &mut self,
        lobby_id_hex: &str,
        contact_id_hex: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .remove_lobby_member(lobby_id(lobby_id_hex)?, contact_id(contact_id_hex)?)
            .map_err(to_js_error)
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
        Ok(array)
    }

    #[wasm_bindgen(js_name = receiveLobby)]
    pub fn receive_lobby(
        &mut self,
        envelope: Vec<u8>,
    ) -> Result<WasmReceivedHydraMessage, JsValue> {
        Ok(WasmReceivedHydraMessage {
            inner: self
                .inner
                .receive_lobby(HydraEnvelope::from_bytes(envelope))
                .map_err(to_js_error)?,
        })
    }

    #[wasm_bindgen(js_name = rekeyLobby)]
    pub fn rekey_lobby(&mut self, lobby_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .rekey_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = closeLobby)]
    pub fn close_lobby(&mut self, lobby_id_hex: &str) -> Result<(), JsValue> {
        self.inner
            .close_lobby(lobby_id(lobby_id_hex)?)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = exportBackup)]
    pub fn export_backup(&self, password: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.export_backup(password).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = importBackup)]
    pub fn import_backup(&mut self, bytes: Vec<u8>, password: &str) -> Result<(), JsValue> {
        self.inner
            .import_backup(bytes, password)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = verifyBackup)]
    pub fn verify_backup(&self, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.inner.verify_backup(bytes).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = storageStatus)]
    pub fn storage_status(&self) -> String {
        let status = self.inner.storage_status();
        format!(
            "{{\"dataDir\":\"{}\",\"identityCount\":{},\"contactCount\":{},\"sessionCount\":{},\"messageCount\":{},\"lobbyCount\":{}}}",
            status.data_dir.display(),
            status.identity_count,
            status.contact_count,
            status.session_count,
            status.message_count,
            status.lobby_count,
        )
    }

    #[wasm_bindgen(js_name = benchmark)]
    pub fn benchmark(&self) -> Result<WasmHydraBenchmarkReport, JsValue> {
        Ok(WasmHydraBenchmarkReport {
            inner: self.inner.benchmark().map_err(to_js_error)?,
        })
    }
}

#[wasm_bindgen]
impl WasmHydraMessage {
    #[wasm_bindgen(js_name = text)]
    pub fn text(text: &str) -> WasmHydraMessage {
        Self {
            inner: HydraMessage::text(text),
        }
    }

    #[wasm_bindgen(js_name = bytes)]
    pub fn bytes(bytes: Vec<u8>) -> WasmHydraMessage {
        Self {
            inner: HydraMessage::bytes(bytes),
        }
    }

    #[wasm_bindgen(js_name = attachBytes)]
    pub fn attach_bytes(
        mut self,
        filename: &str,
        bytes: Vec<u8>,
    ) -> Result<WasmHydraMessage, JsValue> {
        self.inner = self
            .inner
            .attach_bytes(filename, bytes)
            .map_err(to_js_error)?;
        Ok(self)
    }

    #[wasm_bindgen(js_name = attachFile)]
    pub fn attach_file(self, filename: &str, bytes: Vec<u8>) -> Result<WasmHydraMessage, JsValue> {
        self.attach_bytes(filename, bytes)
    }
}

#[wasm_bindgen]
impl WasmReceivedHydraMessage {
    #[wasm_bindgen(js_name = from)]
    pub fn from(&self) -> String {
        self.inner.from().hex()
    }

    #[wasm_bindgen(js_name = messageId)]
    pub fn message_id(&self) -> f64 {
        self.inner.message_id().value() as f64
    }

    #[wasm_bindgen(js_name = lobbyId)]
    pub fn lobby_id(&self) -> Option<String> {
        self.inner.lobby_id().map(|id| id.hex())
    }

    #[wasm_bindgen(js_name = plaintext)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.inner.plaintext().to_vec()
    }

    #[wasm_bindgen(js_name = text)]
    pub fn text(&self) -> Result<String, JsValue> {
        self.inner.text().map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = attachmentCount)]
    pub fn attachment_count(&self) -> usize {
        self.inner.attachments().len()
    }

    #[wasm_bindgen(js_name = attachmentFilename)]
    pub fn attachment_filename(&self, index: usize) -> Result<String, JsValue> {
        Ok(self
            .inner
            .attachments()
            .get(index)
            .ok_or_else(|| JsValue::from_str("attachment index out of range"))?
            .filename()
            .to_string())
    }

    #[wasm_bindgen(js_name = attachmentBytes)]
    pub fn attachment_bytes(&self, index: usize) -> Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .attachments()
            .get(index)
            .ok_or_else(|| JsValue::from_str("attachment index out of range"))?
            .bytes()
            .to_vec())
    }

    #[wasm_bindgen(js_name = attachmentIsFile)]
    pub fn attachment_is_file(&self, index: usize) -> Result<bool, JsValue> {
        Ok(self
            .inner
            .attachments()
            .get(index)
            .ok_or_else(|| JsValue::from_str("attachment index out of range"))?
            .is_file())
    }

    #[wasm_bindgen(js_name = attachmentIsBytes)]
    pub fn attachment_is_bytes(&self, index: usize) -> Result<bool, JsValue> {
        Ok(self
            .inner
            .attachments()
            .get(index)
            .ok_or_else(|| JsValue::from_str("attachment index out of range"))?
            .is_bytes())
    }
}

#[wasm_bindgen]
impl WasmHydraLobbyEnvelope {
    #[wasm_bindgen(js_name = recipient)]
    pub fn recipient(&self) -> String {
        self.inner.recipient().hex()
    }

    #[wasm_bindgen(js_name = envelope)]
    pub fn envelope(&self) -> Uint8Array {
        Uint8Array::from(self.inner.envelope().as_bytes())
    }
}

#[wasm_bindgen]
impl WasmHydraBenchmarkReport {
    #[wasm_bindgen(getter)]
    pub fn suite(&self) -> String {
        self.inner.suite.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn iterations(&self) -> u32 {
        self.inner.iterations
    }

    #[wasm_bindgen(getter, js_name = handshakeAvgMs)]
    pub fn handshake_avg_ms(&self) -> f64 {
        self.inner.handshake_avg_ms
    }

    #[wasm_bindgen(getter, js_name = sendReceiveAvgMs)]
    pub fn send_receive_avg_ms(&self) -> f64 {
        self.inner.send_receive_avg_ms
    }

    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"suite\":\"{}\",\"iterations\":{},\"handshakeAvgMs\":{},\"sendReceiveAvgMs\":{}}}",
            self.inner.suite,
            self.inner.iterations,
            self.inner.handshake_avg_ms,
            self.inner.send_receive_avg_ms,
        )
    }
}

fn contact_id(hex: &str) -> Result<ContactId, JsValue> {
    ContactId::from_hex(hex).map_err(to_js_error)
}

fn lobby_id(hex: &str) -> Result<LobbyId, JsValue> {
    LobbyId::from_hex(hex).map_err(to_js_error)
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
