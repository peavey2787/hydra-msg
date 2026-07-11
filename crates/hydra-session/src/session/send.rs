use hydra_core::types::{ContentKind, EnvelopeClass, OuterMode};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};
use hydra_envelope::{encode_outer_header, encode_protected_record, OuterHeader, ProtectedRecord};

use crate::{ratchet::derive_step, SessionError, SessionResult};

use super::{
    envelope_bounds::{bounded_data_class, smallest_class, smallest_standard_or_full},
    OutboundMessage, SessionPhase, SessionState,
};

impl SessionState {
    pub fn send_data(&mut self, content: &[u8]) -> SessionResult<OutboundMessage> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::InvalidState);
        }
        let class = smallest_class(content.len()).ok_or(SessionError::InvalidPayload)?;
        self.send_record(ContentKind::Data, class, content)
    }

    #[doc(hidden)]
    pub fn send_data_with_envelope_bounds(
        &mut self,
        content: &[u8],
        min_envelope_size: usize,
        max_envelope_size: usize,
    ) -> SessionResult<OutboundMessage> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::InvalidState);
        }
        let class = bounded_data_class(content.len(), min_envelope_size, max_envelope_size)
            .ok_or(SessionError::InvalidPayload)?;
        self.send_record(ContentKind::Data, class, content)
    }

    pub fn send_refresh_control(
        &mut self,
        kind: ContentKind,
        content: &[u8],
    ) -> SessionResult<OutboundMessage> {
        if self.phase != SessionPhase::Refreshing
            || !matches!(kind, ContentKind::RefreshInit | ContentKind::RefreshResp)
        {
            return Err(SessionError::InvalidState);
        }
        self.send_record(kind, EnvelopeClass::Standard, content)
    }

    pub fn send_signed_control(
        &mut self,
        kind: ContentKind,
        content: &[u8],
    ) -> SessionResult<OutboundMessage> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::InvalidState);
        }
        let class = match kind {
            ContentKind::IdentityRotation => EnvelopeClass::Standard,
            ContentKind::DeviceRevocation => {
                smallest_standard_or_full(content.len()).ok_or(SessionError::InvalidPayload)?
            }
            _ => return Err(SessionError::InvalidState),
        };
        self.send_record(kind, class, content)
    }

    pub fn send_close(&mut self, generic_reason_code: u16) -> SessionResult<OutboundMessage> {
        if !matches!(
            self.phase,
            SessionPhase::Established | SessionPhase::Refreshing
        ) {
            return Err(SessionError::InvalidState);
        }
        let outbound = self.send_record(
            ContentKind::Close,
            EnvelopeClass::Lite,
            &generic_reason_code.to_be_bytes(),
        )?;
        self.phase = SessionPhase::Closing;
        self.active_refresh_id = None;
        Ok(outbound)
    }

    pub(super) fn send_record(
        &mut self,
        content_kind: ContentKind,
        class: EnvelopeClass,
        content: &[u8],
    ) -> SessionResult<OutboundMessage> {
        let index = self.sending_chain.next_index();
        self.seal_record(
            class,
            ProtectedRecord {
                content_kind,
                session_or_group_id: self.session_id,
                sender_id: [0; 32],
                epoch: 0,
                state_version: 0,
                message_index: index,
                content: content.to_vec(),
            },
        )
    }

    pub(super) fn seal_record(
        &mut self,
        class: EnvelopeClass,
        record: ProtectedRecord,
    ) -> SessionResult<OutboundMessage> {
        let index = self.sending_chain.next_index();
        if index == u64::MAX {
            return Err(SessionError::CounterExhausted);
        }
        if record.message_index != index {
            return Err(SessionError::InvalidState);
        }
        let step = derive_step(self.sending_chain.key(), &self.session_id, index)?;
        let plaintext =
            encode_protected_record(class, &record).map_err(|_| SessionError::InvalidPayload)?;
        self.seal_plaintext(class, index, step, &plaintext)
    }

    pub(super) fn seal_plaintext(
        &mut self,
        class: EnvelopeClass,
        index: u64,
        step: crate::ratchet::RatchetStep,
        plaintext: &[u8],
    ) -> SessionResult<OutboundMessage> {
        let header = encode_outer_header(&OuterHeader::new(
            OuterMode::Protected,
            class,
            step.route_tag,
            index,
        ))
        .map_err(|_| SessionError::InvalidEnvelope)?;
        let body = RustCryptoBackend::aead_seal(&step.aead_key, &[0_u8; 12], &header, plaintext)
            .map_err(|_| SessionError::AuthenticationFailed)?;
        let mut envelope = Vec::with_capacity(class.envelope_size());
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&body);
        self.sending_chain.install(step.next_chain_key, index + 1);
        Ok(OutboundMessage { index, envelope })
    }
}
