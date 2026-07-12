mod types;

pub use types::{
    HydraAttachment, HydraAttachmentSource, HydraMessage, MessageId, ReceivedHydraMessage,
};
pub(crate) use types::{MessageUsage, StoredMessage};

use crate::{
    codec::*,
    limits::{
        reject_collection_growth, reject_decoded_collection_growth, reject_encoded_size,
        reject_input_size, MAX_MESSAGES, MAX_MESSAGES_PER_CONTACT, MAX_MESSAGE_IMPORT_BYTES,
        MAX_STORED_MESSAGE_BYTES, MAX_STORED_MESSAGE_BYTES_PER_CONTACT,
    },
    packet_fragments::FragmentScope,
    ContactId, Hydra, HydraEnvelope, HydraMsgError, HydraResult, MESSAGES_MAGIC,
};
use std::collections::HashMap;

impl Hydra {
    pub fn send(
        &mut self,
        contact_id: ContactId,
        message: impl Into<HydraMessage>,
    ) -> HydraResult<Vec<HydraEnvelope>> {
        self.active_unlocked_record()?;
        self.reject_send_when_refresh_required(contact_id)?;
        let message = message.into();
        let payload = pack_message(&message)?;
        self.ensure_message_capacity(contact_id, payload.len())?;
        let mut packets = Vec::new();
        for payload in self.payloads_for_packets(FragmentScope::Direct, &payload)? {
            packets.push(self.seal_payload_for_contact(contact_id, &payload)?);
        }
        self.store_message(contact_id, false, message.plaintext, message.attachments)?;
        self.persist()?;
        self.record_outbound_application_message(contact_id)?;
        Ok(packets)
    }

    #[must_use]
    pub fn list_messages(&self, contact_id: ContactId) -> Vec<MessageId> {
        self.messages
            .iter()
            .filter(|message| message.contact_id == contact_id)
            .map(|message| message.id)
            .collect()
    }

    pub fn get_message(&self, message_id: MessageId) -> HydraResult<ReceivedHydraMessage> {
        let stored = self
            .messages
            .iter()
            .find(|message| message.id == message_id)
            .ok_or(HydraMsgError::MessageNotFound)?;
        Ok(ReceivedHydraMessage {
            from: stored.contact_id,
            message_id: stored.id,
            lobby_id: None,
            plaintext: stored.plaintext.clone(),
            attachments: stored.attachments.clone(),
        })
    }

    pub fn delete_message(&mut self, message_id: MessageId) -> HydraResult<()> {
        let previous_snapshot = self.encode_state_snapshot()?;
        let position = self
            .messages
            .iter()
            .position(|message| message.id == message_id)
            .ok_or(HydraMsgError::MessageNotFound)?;
        let size = stored_message_size(
            &self.messages[position].plaintext,
            &self.messages[position].attachments,
        )?;
        let contact_id = self.messages[position].contact_id;
        self.messages.remove(position);
        self.release_message_usage(contact_id, size)?;
        if let Err(error) = self.persist() {
            let _ = self.apply_state_snapshot(&previous_snapshot);
            return Err(error);
        }
        Ok(())
    }

    pub fn clear_messages(&mut self, contact_id: ContactId) -> HydraResult<()> {
        self.messages
            .retain(|message| message.contact_id != contact_id);
        self.rebuild_message_usage()?;
        self.persist()?;
        Ok(())
    }

    pub fn export_messages(&self) -> HydraResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(MESSAGES_MAGIC);
        for message in &self.messages {
            out.extend_from_slice(encode_message_line(message).as_bytes());
            out.push(b'\n');
            reject_input_size(out.len(), MAX_MESSAGE_IMPORT_BYTES, "messages export size")?;
        }
        Ok(out)
    }

    pub fn import_messages(&mut self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        let bytes = bytes.as_ref();
        reject_encoded_size(
            bytes.len(),
            MAX_MESSAGE_IMPORT_BYTES,
            "messages import size",
        )?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| HydraMsgError::InvalidEncoding("messages export is not utf-8"))?;
        if !text.starts_with(std::str::from_utf8(MESSAGES_MAGIC).unwrap_or_default()) {
            return Err(HydraMsgError::InvalidEncoding("messages export magic"));
        }

        let mut imported = Vec::new();
        let mut imported_usage = HashMap::<ContactId, MessageUsage>::new();
        let mut imported_bytes = 0usize;
        let mut seen_ids = self
            .messages
            .iter()
            .map(|message| message.id)
            .collect::<std::collections::HashSet<_>>();
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            reject_decoded_collection_growth(
                imported.len(),
                1,
                MAX_MESSAGES,
                "messages import count",
            )?;
            let message = decode_message_line(line)?;
            if !seen_ids.insert(message.id) {
                return Err(HydraMsgError::InvalidEncoding("message id duplicate"));
            }
            let size = stored_message_size(&message.plaintext, &message.attachments)?;
            imported_bytes = imported_bytes
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidEncoding("messages import byte count"))?;
            reject_encoded_size(
                imported_bytes,
                MAX_STORED_MESSAGE_BYTES,
                "messages import byte count",
            )?;
            let usage = imported_usage.entry(message.contact_id).or_default();
            usage.count = usage
                .count
                .checked_add(1)
                .ok_or(HydraMsgError::InvalidEncoding("messages import count"))?;
            usage.bytes = usage
                .bytes
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidEncoding("messages import byte count"))?;
            if usage.count > MAX_MESSAGES_PER_CONTACT
                || usage.bytes > MAX_STORED_MESSAGE_BYTES_PER_CONTACT
            {
                return Err(HydraMsgError::InvalidEncoding(
                    "messages import per-contact limit",
                ));
            }
            imported.push(message);
        }

        reject_collection_growth(
            self.messages.len(),
            imported.len(),
            MAX_MESSAGES,
            "message limit reached",
        )?;
        reject_collection_growth(
            self.stored_message_bytes,
            imported_bytes,
            MAX_STORED_MESSAGE_BYTES,
            "stored message byte limit reached",
        )?;
        for (contact_id, additional) in &imported_usage {
            let existing = self
                .message_usage
                .get(contact_id)
                .copied()
                .unwrap_or_default();
            reject_collection_growth(
                existing.count,
                additional.count,
                MAX_MESSAGES_PER_CONTACT,
                "contact message limit reached",
            )?;
            reject_collection_growth(
                existing.bytes,
                additional.bytes,
                MAX_STORED_MESSAGE_BYTES_PER_CONTACT,
                "contact message byte limit reached",
            )?;
        }

        for message in imported {
            self.next_message_id = self.next_message_id.max(message.id.0.saturating_add(1));
            self.messages.push(message);
        }
        self.stored_message_bytes += imported_bytes;
        for (contact_id, additional) in imported_usage {
            let usage = self.message_usage.entry(contact_id).or_default();
            usage.count += additional.count;
            usage.bytes += additional.bytes;
        }
        self.persist()?;
        Ok(())
    }

    pub(crate) fn ensure_message_capacity(
        &self,
        contact_id: ContactId,
        additional_bytes: usize,
    ) -> HydraResult<()> {
        reject_collection_growth(
            self.messages.len(),
            1,
            MAX_MESSAGES,
            "message limit reached",
        )?;
        reject_collection_growth(
            self.stored_message_bytes,
            additional_bytes,
            MAX_STORED_MESSAGE_BYTES,
            "stored message byte limit reached",
        )?;
        let usage = self
            .message_usage
            .get(&contact_id)
            .copied()
            .unwrap_or_default();
        reject_collection_growth(
            usage.count,
            1,
            MAX_MESSAGES_PER_CONTACT,
            "contact message limit reached",
        )?;
        reject_collection_growth(
            usage.bytes,
            additional_bytes,
            MAX_STORED_MESSAGE_BYTES_PER_CONTACT,
            "contact message byte limit reached",
        )
    }

    pub(crate) fn store_message(
        &mut self,
        contact_id: ContactId,
        inbound: bool,
        plaintext: Vec<u8>,
        attachments: Vec<HydraAttachment>,
    ) -> HydraResult<MessageId> {
        let size = stored_message_size(&plaintext, &attachments)?;
        self.ensure_message_capacity(contact_id, size)?;
        let id = MessageId(self.next_message_id);
        self.next_message_id = self.next_message_id.saturating_add(1);
        self.messages.push(StoredMessage {
            id,
            contact_id,
            inbound,
            plaintext,
            attachments,
        });
        self.record_message_usage(contact_id, size);
        Ok(id)
    }

    pub(crate) fn rebuild_message_usage(&mut self) -> HydraResult<()> {
        let mut usage = HashMap::<ContactId, MessageUsage>::new();
        let mut total_bytes = 0usize;
        for message in &self.messages {
            let size = stored_message_size(&message.plaintext, &message.attachments)?;
            total_bytes = total_bytes
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidEncoding("stored message byte count"))?;
            if total_bytes > MAX_STORED_MESSAGE_BYTES {
                return Err(HydraMsgError::InvalidEncoding("stored message byte limit"));
            }
            let entry = usage.entry(message.contact_id).or_default();
            entry.count = entry
                .count
                .checked_add(1)
                .ok_or(HydraMsgError::InvalidEncoding("stored message count"))?;
            entry.bytes = entry
                .bytes
                .checked_add(size)
                .ok_or(HydraMsgError::InvalidEncoding("stored message byte count"))?;
            if entry.count > MAX_MESSAGES_PER_CONTACT
                || entry.bytes > MAX_STORED_MESSAGE_BYTES_PER_CONTACT
            {
                return Err(HydraMsgError::InvalidEncoding(
                    "stored messages per-contact limit",
                ));
            }
        }
        self.message_usage = usage;
        self.stored_message_bytes = total_bytes;
        Ok(())
    }

    fn record_message_usage(&mut self, contact_id: ContactId, size: usize) {
        self.stored_message_bytes += size;
        let usage = self.message_usage.entry(contact_id).or_default();
        usage.count += 1;
        usage.bytes += size;
    }

    fn release_message_usage(&mut self, contact_id: ContactId, size: usize) -> HydraResult<()> {
        self.stored_message_bytes = self
            .stored_message_bytes
            .checked_sub(size)
            .ok_or(HydraMsgError::InvalidEncoding("stored message byte count"))?;
        let remove_entry = {
            let usage = self
                .message_usage
                .get_mut(&contact_id)
                .ok_or(HydraMsgError::InvalidEncoding("stored message usage"))?;
            usage.count = usage
                .count
                .checked_sub(1)
                .ok_or(HydraMsgError::InvalidEncoding("stored message count"))?;
            usage.bytes = usage
                .bytes
                .checked_sub(size)
                .ok_or(HydraMsgError::InvalidEncoding("stored message byte count"))?;
            usage.count == 0
        };
        if remove_entry {
            self.message_usage.remove(&contact_id);
        }
        Ok(())
    }
}
