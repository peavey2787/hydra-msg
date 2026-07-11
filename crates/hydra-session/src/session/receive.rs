use hydra_core::{
    protocol::replay::ReplayError,
    types::{ContentKind, EnvelopeClass, OuterMode},
    MAX_SKIP, OUTER_HEADER_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_envelope::{decode_outer_header, decode_protected_record, OuterHeader, ProtectedRecord};

use crate::{
    ratchet::{constant_time_tag_eq, derive_aead_key, derive_route_tag, derive_step},
    SessionError, SessionResult,
};

use super::{
    envelope_bounds::smallest_standard_or_full, Direction, ReceivedMessage, SessionPhase,
    SessionState,
};

impl SessionState {
    pub fn receive(&mut self, envelope: &[u8]) -> SessionResult<ReceivedMessage> {
        self.receive_validated(envelope, |record| {
            if matches!(record.content_kind, ContentKind::Data | ContentKind::Close) {
                Ok(())
            } else {
                Err(SessionError::AuthenticationFailed)
            }
        })
    }

    pub fn receive_validated<F>(
        &mut self,
        envelope: &[u8],
        validator: F,
    ) -> SessionResult<ReceivedMessage>
    where
        F: FnOnce(&ProtectedRecord) -> SessionResult<()>,
    {
        if !matches!(
            self.phase,
            SessionPhase::Established | SessionPhase::Refreshing | SessionPhase::Closing
        ) {
            return Err(SessionError::InvalidState);
        }
        let header = decode_outer_header(envelope).map_err(|_| SessionError::InvalidEnvelope)?;
        if header.mode != OuterMode::Protected || header.counter == u64::MAX {
            return Err(SessionError::InvalidEnvelope);
        }
        self.replay
            .check(header.counter)
            .map_err(map_replay_error)?;

        let record = if header.counter < self.receiving_chain.next_index() {
            self.receive_skipped(&header, envelope, validator)?
        } else {
            self.receive_current_or_future(&header, envelope, validator)?
        };
        let received = ReceivedMessage {
            index: record.message_index,
            content_kind: record.content_kind,
            content: record.content,
        };
        if received.content_kind == ContentKind::Close {
            self.full_wipe();
        }
        Ok(received)
    }

    fn receive_skipped<F>(
        &mut self,
        header: &OuterHeader,
        envelope: &[u8],
        validator: F,
    ) -> SessionResult<ProtectedRecord>
    where
        F: FnOnce(&ProtectedRecord) -> SessionResult<()>,
    {
        let direction = self.receiving_direction();
        let message_key = self
            .skipped_keys
            .get(&self.session_id, direction, header.counter)
            .ok_or(SessionError::MessageTooOld)?;
        let expected_route = derive_route_tag(message_key, &self.session_id, header.counter);
        if !constant_time_tag_eq(&expected_route, &header.route_tag) {
            return Err(SessionError::AuthenticationFailed);
        }
        let aead_key = derive_aead_key(message_key, &self.session_id, header.counter)?;
        let record = open_and_validate(&aead_key, header, envelope, &self.session_id, self.phase)?;
        validator(&record)?;

        let mut replay = self.replay.clone();
        replay.mark(header.counter).map_err(map_replay_error)?;
        self.skipped_keys
            .remove(&self.session_id, direction, header.counter)?;
        self.replay = replay;
        Ok(record)
    }

    fn receive_current_or_future<F>(
        &mut self,
        header: &OuterHeader,
        envelope: &[u8],
        validator: F,
    ) -> SessionResult<ProtectedRecord>
    where
        F: FnOnce(&ProtectedRecord) -> SessionResult<()>,
    {
        let next = self.receiving_chain.next_index();
        let gap = header
            .counter
            .checked_sub(next)
            .ok_or(SessionError::InvalidState)?;
        if gap > MAX_SKIP as u64 {
            return Err(SessionError::MessageTooFarAhead);
        }
        let gap_usize = usize::try_from(gap).map_err(|_| SessionError::MessageTooFarAhead)?;
        self.skipped_keys.ensure_capacity_for(gap_usize)?;

        let mut cursor = next;
        let mut provisional_chain: Option<SecretBytes<32>> = None;
        let mut skipped = Vec::with_capacity(gap_usize);
        let final_step = loop {
            let chain_key = provisional_chain
                .as_ref()
                .unwrap_or_else(|| self.receiving_chain.key());
            let step = derive_step(chain_key, &self.session_id, cursor)?;
            if cursor == header.counter {
                break step;
            }
            skipped.push((cursor, step.message_key));
            provisional_chain = Some(step.next_chain_key);
            cursor = cursor
                .checked_add(1)
                .ok_or(SessionError::CounterExhausted)?;
        };

        if !constant_time_tag_eq(&final_step.route_tag, &header.route_tag) {
            return Err(SessionError::AuthenticationFailed);
        }
        let record = open_and_validate(
            &final_step.aead_key,
            header,
            envelope,
            &self.session_id,
            self.phase,
        )?;
        validator(&record)?;

        let mut replay = self.replay.clone();
        replay.mark(header.counter).map_err(map_replay_error)?;
        let direction = self.receiving_direction();
        self.skipped_keys
            .commit_batch(self.session_id, direction, skipped);
        self.receiving_chain
            .install(final_step.next_chain_key, header.counter + 1);
        self.replay = replay;
        Ok(record)
    }

    #[must_use]
    fn receiving_direction(&self) -> Direction {
        match self.role {
            super::SessionRole::Initiator => Direction::ResponderToInitiator,
            super::SessionRole::Responder => Direction::InitiatorToResponder,
        }
    }
}

fn open_and_validate(
    aead_key: &SecretBytes<32>,
    header: &OuterHeader,
    envelope: &[u8],
    session_id: &[u8; 32],
    phase: SessionPhase,
) -> SessionResult<ProtectedRecord> {
    let plaintext = RustCryptoBackend::aead_open(
        aead_key,
        &[0_u8; 12],
        &envelope[..OUTER_HEADER_SIZE],
        &envelope[OUTER_HEADER_SIZE..],
    )
    .map_err(|_| SessionError::AuthenticationFailed)?;
    let record = decode_protected_record(header.envelope_class, &plaintext)
        .map_err(|_| SessionError::AuthenticationFailed)?;
    if &record.session_or_group_id != session_id
        || record.sender_id != [0; 32]
        || record.epoch != 0
        || record.state_version != 0
        || record.message_index != header.counter
        || !valid_class_and_content(&record, header.envelope_class)
        || (phase == SessionPhase::Closing && record.content_kind != ContentKind::Close)
    {
        return Err(SessionError::AuthenticationFailed);
    }
    Ok(record)
}

fn valid_class_and_content(record: &ProtectedRecord, class: EnvelopeClass) -> bool {
    match record.content_kind {
        ContentKind::Data => record.content.len() <= class.max_content_size(),
        ContentKind::RefreshInit | ContentKind::RefreshResp => class == EnvelopeClass::Standard,
        ContentKind::IdentityRotation => class == EnvelopeClass::Standard,
        ContentKind::DeviceRevocation => {
            smallest_standard_or_full(record.content.len()) == Some(class)
        }
        ContentKind::Close => class == EnvelopeClass::Lite && record.content.len() == 2,
        _ => false,
    }
}

fn map_replay_error(error: ReplayError) -> SessionError {
    match error {
        ReplayError::Replay => SessionError::ReplayDetected,
        ReplayError::TooOld => SessionError::MessageTooOld,
    }
}

#[cfg(test)]
mod tests;
