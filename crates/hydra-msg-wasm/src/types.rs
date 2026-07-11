use crate::{hex_encode, to_js_error};
use hydra_msg::{HydraBenchmarkReport, HydraLobbyEnvelope, HydraMessage, ReceivedHydraMessage};
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmHydraMessage {
    pub(crate) inner: HydraMessage,
}

#[wasm_bindgen]
pub struct WasmReceivedHydraMessage {
    pub(crate) inner: ReceivedHydraMessage,
}

#[wasm_bindgen]
pub struct WasmHydraLobbyEnvelope {
    pub(crate) inner: HydraLobbyEnvelope,
}

#[wasm_bindgen]
pub struct WasmHydraBenchmarkReport {
    pub(crate) inner: HydraBenchmarkReport,
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

    #[wasm_bindgen(js_name = routingHint)]
    pub fn routing_hint(&self) -> Vec<u8> {
        self.inner.routing_hint().bytes().to_vec()
    }

    #[wasm_bindgen(js_name = routingHintHex)]
    pub fn routing_hint_hex(&self) -> String {
        hex_encode(&self.inner.routing_hint().bytes())
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
