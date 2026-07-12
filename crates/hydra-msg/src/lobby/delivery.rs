use crate::{
    codec::*,
    limits::{MAX_LOBBY_OUTBOUND_ENVELOPE_BYTES, MAX_LOBBY_OUTBOUND_PACKETS},
    packet_fragments::{FragmentKind, FragmentScope},
    ContactId, Hydra, HydraLobbyEnvelope, HydraLobbyRoutingHint, HydraMessage, HydraMsgError,
    HydraResult, LobbyId, MessageId, ReceivedHydraMessage,
};

impl Hydra {
    pub fn send_lobby(
        &mut self,
        lobby_id: LobbyId,
        message: impl Into<HydraMessage>,
    ) -> HydraResult<Vec<HydraLobbyEnvelope>> {
        self.active_unlocked_record()?;
        let lobby = self.get_lobby(lobby_id)?;
        let members = lobby.members;
        if members.is_empty() {
            return Err(HydraMsgError::InvalidInput("lobby has no members"));
        }
        for member in &members {
            let contact = self.require_contact(*member)?;
            if contact.blocked {
                return Err(HydraMsgError::InvalidInput("lobby member is blocked"));
            }
            if self
                .sessions
                .get(member)
                .is_none_or(|session| session.closed)
            {
                return Err(HydraMsgError::SessionNotFound);
            }
            self.reject_send_when_refresh_required(*member)?;
        }
        let message = message.into();
        let packed_message = pack_message(&message)?;
        let lobby_payload = pack_lobby_payload(lobby_id, &packed_message)?;
        let payloads = self.payloads_for_packets(FragmentScope::Lobby(lobby_id), &lobby_payload)?;
        let packet_count = members
            .len()
            .checked_mul(payloads.len())
            .ok_or(HydraMsgError::InvalidInput("lobby outbound packet count"))?;
        if packet_count > MAX_LOBBY_OUTBOUND_PACKETS {
            return Err(HydraMsgError::InvalidInput(
                "lobby outbound packet limit reached",
            ));
        }
        let envelope_size = self.envelope_size_bounds()?.1;
        let total_envelope_bytes = packet_count
            .checked_mul(envelope_size)
            .ok_or(HydraMsgError::InvalidInput("lobby outbound byte count"))?;
        if total_envelope_bytes > MAX_LOBBY_OUTBOUND_ENVELOPE_BYTES {
            return Err(HydraMsgError::InvalidInput(
                "lobby outbound byte limit reached",
            ));
        }
        let mut envelopes = Vec::with_capacity(packet_count);
        for member in &members {
            for payload in &payloads {
                let routing_hint = HydraLobbyRoutingHint::from_bytes(random_array::<32>()?);
                envelopes.push(HydraLobbyEnvelope {
                    recipient: *member,
                    routing_hint,
                    envelope: self.seal_payload_for_contact(*member, payload)?,
                });
            }
        }
        self.persist()?;
        for member in members {
            self.record_outbound_application_message(member)?;
        }
        Ok(envelopes)
    }

    pub fn receive_lobby(
        &mut self,
        envelope: impl AsRef<[u8]>,
    ) -> HydraResult<Option<ReceivedHydraMessage>> {
        let (from, payload) = self.open_lobby_transport_payload_from_contact(envelope.as_ref())?;
        let Some((lobby_payload, fragment_lobby_id)) =
            self.receive_fragmented_payload(from, FragmentKind::Lobby, &payload)?
        else {
            return Ok(None);
        };
        let (lobby_id, packed_message) = unpack_lobby_payload(&lobby_payload)?;
        if fragment_lobby_id.is_some_and(|scoped_id| scoped_id != lobby_id) {
            return Err(HydraMsgError::InvalidEncoding(
                "fragment lobby scope mismatch",
            ));
        }
        let message = self.receive_open_lobby_payload(from, lobby_id, &packed_message)?;
        self.persist()?;
        Ok(Some(message))
    }

    pub(crate) fn receive_open_lobby_payload(
        &mut self,
        from: ContactId,
        lobby_id: LobbyId,
        packed_message: &[u8],
    ) -> HydraResult<ReceivedHydraMessage> {
        let lobby = self.get_lobby(lobby_id)?;
        if !lobby.members.contains(&from) {
            return Err(HydraMsgError::InvalidInput(
                "lobby message sender is not a member",
            ));
        }
        let message = unpack_message(
            packed_message,
            from,
            MessageId(self.next_message_id),
            Some(lobby_id),
        )?;
        self.store_message(
            from,
            true,
            message.plaintext.clone(),
            message.attachments.clone(),
        )?;
        Ok(message)
    }
}
