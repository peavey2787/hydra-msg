use crate::{
    codec::*, packet_fragments::FragmentKind, Hydra, HydraResult, MessageId, ReceivedHydraMessage,
};

impl Hydra {
    pub fn receive(
        &mut self,
        envelope: impl AsRef<[u8]>,
    ) -> HydraResult<Option<ReceivedHydraMessage>> {
        let (from, payload) = self.open_payload_from_contact(envelope.as_ref())?;
        let Some((payload, fragment_lobby_id)) =
            self.receive_fragmented_payload(from, FragmentKind::Direct, &payload)?
        else {
            return Ok(None);
        };
        if fragment_lobby_id.is_some() {
            return Err(crate::HydraMsgError::InvalidEncoding(
                "direct fragment lobby scope",
            ));
        }
        let message = unpack_message(&payload, from, MessageId(self.next_message_id), None)?;
        self.store_message(
            from,
            true,
            message.plaintext.clone(),
            message.attachments.clone(),
        )?;
        self.persist()?;
        Ok(Some(message))
    }
}
