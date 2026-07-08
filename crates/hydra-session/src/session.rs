use hydra_core::{
    protocol::replay::{ReplayError, ReplayWindow, ReplayWindowSnapshot},
    types::{ContentKind, EnvelopeClass, OuterMode},
    MAX_SKIP, OUTER_HEADER_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_envelope::{
    decode_outer_header, decode_protected_record, encode_outer_header, encode_protected_record,
    OuterHeader, ProtectedRecord,
};

use crate::{
    key_derivation::InitialSessionSecrets,
    ratchet::{
        constant_time_tag_eq, derive_aead_key, derive_route_tag, derive_step, DirectionChain,
        DirectionChainSnapshot,
    },
    refresh::{derive_refresh_candidate, RefreshCandidate, RefreshRole, VerifiedRefresh},
    skipped_keys::{SkippedKeyStore, SkippedMessageKeySnapshot},
    SessionError, SessionResult,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    InitiatorToResponder,
    ResponderToInitiator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Established,
    Refreshing,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshIdDecision {
    Accepted,
    ReplacedLocal,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutboundMessage {
    pub index: u64,
    pub envelope: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub index: u64,
    pub content_kind: ContentKind,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStateSnapshot {
    pub role: SessionRole,
    pub phase: SessionPhase,
    pub session_id: [u8; 32],
    pub transcript_hash: [u8; 64],
    pub local_identity_fingerprint: [u8; 32],
    pub remote_identity_fingerprint: [u8; 32],
    pub refresh_root: [u8; 32],
    pub sending_chain: DirectionChainSnapshot,
    pub receiving_chain: DirectionChainSnapshot,
    pub skipped_keys: Vec<SkippedMessageKeySnapshot>,
    pub replay: ReplayWindowSnapshot,
    pub active_refresh_id: Option<[u8; 32]>,
}

pub struct SessionState {
    role: SessionRole,
    phase: SessionPhase,
    session_id: [u8; 32],
    transcript_hash: [u8; 64],
    local_identity_fingerprint: [u8; 32],
    remote_identity_fingerprint: [u8; 32],
    refresh_root: SecretBytes<32>,
    sending_chain: DirectionChain,
    receiving_chain: DirectionChain,
    skipped_keys: SkippedKeyStore,
    replay: ReplayWindow,
    active_refresh_id: Option<[u8; 32]>,
}

impl SessionState {
    #[must_use]
    pub fn established(
        role: SessionRole,
        transcript_hash: [u8; 64],
        local_identity_fingerprint: [u8; 32],
        remote_identity_fingerprint: [u8; 32],
        secrets: InitialSessionSecrets,
    ) -> Self {
        let (sending_chain, receiving_chain) = match role {
            SessionRole::Initiator => (
                DirectionChain::new(secrets.chain_i2r),
                DirectionChain::new(secrets.chain_r2i),
            ),
            SessionRole::Responder => (
                DirectionChain::new(secrets.chain_r2i),
                DirectionChain::new(secrets.chain_i2r),
            ),
        };
        Self {
            role,
            phase: SessionPhase::Established,
            session_id: secrets.session_id,
            transcript_hash,
            local_identity_fingerprint,
            remote_identity_fingerprint,
            refresh_root: secrets.refresh_root,
            sending_chain,
            receiving_chain,
            skipped_keys: SkippedKeyStore::default(),
            replay: ReplayWindow::default(),
            active_refresh_id: None,
        }
    }

    #[must_use]
    pub fn export_snapshot(&self) -> SessionStateSnapshot {
        SessionStateSnapshot {
            role: self.role,
            phase: self.phase,
            session_id: self.session_id,
            transcript_hash: self.transcript_hash,
            local_identity_fingerprint: self.local_identity_fingerprint,
            remote_identity_fingerprint: self.remote_identity_fingerprint,
            refresh_root: *self.refresh_root.expose_secret(),
            sending_chain: self.sending_chain.export_snapshot(),
            receiving_chain: self.receiving_chain.export_snapshot(),
            skipped_keys: self.skipped_keys.export_snapshot(),
            replay: self.replay.export_snapshot(),
            active_refresh_id: self.active_refresh_id,
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: SessionStateSnapshot) -> Self {
        Self {
            role: snapshot.role,
            phase: snapshot.phase,
            session_id: snapshot.session_id,
            transcript_hash: snapshot.transcript_hash,
            local_identity_fingerprint: snapshot.local_identity_fingerprint,
            remote_identity_fingerprint: snapshot.remote_identity_fingerprint,
            refresh_root: SecretBytes::from_array(snapshot.refresh_root),
            sending_chain: DirectionChain::from_snapshot(snapshot.sending_chain),
            receiving_chain: DirectionChain::from_snapshot(snapshot.receiving_chain),
            skipped_keys: SkippedKeyStore::from_snapshot(snapshot.skipped_keys),
            replay: ReplayWindow::from_snapshot(snapshot.replay),
            active_refresh_id: snapshot.active_refresh_id,
        }
    }

    #[must_use]
    pub const fn role(&self) -> SessionRole {
        self.role
    }

    #[must_use]
    pub const fn phase(&self) -> SessionPhase {
        self.phase
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    #[must_use]
    pub const fn transcript_hash(&self) -> &[u8; 64] {
        &self.transcript_hash
    }

    #[must_use]
    pub const fn local_identity_fingerprint(&self) -> &[u8; 32] {
        &self.local_identity_fingerprint
    }

    #[must_use]
    pub const fn remote_identity_fingerprint(&self) -> &[u8; 32] {
        &self.remote_identity_fingerprint
    }

    #[must_use]
    pub const fn next_send_index(&self) -> u64 {
        self.sending_chain.next_index()
    }

    #[must_use]
    pub const fn next_receive_index(&self) -> u64 {
        self.receiving_chain.next_index()
    }

    #[must_use]
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }

    #[must_use]
    fn receiving_direction(&self) -> Direction {
        match self.role {
            SessionRole::Initiator => Direction::ResponderToInitiator,
            SessionRole::Responder => Direction::InitiatorToResponder,
        }
    }

    pub fn send_data(&mut self, content: &[u8]) -> SessionResult<OutboundMessage> {
        if self.phase != SessionPhase::Established {
            return Err(SessionError::InvalidState);
        }
        let class = smallest_class(content.len()).ok_or(SessionError::InvalidPayload)?;
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

    fn send_record(
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

    fn seal_record(
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

    fn seal_plaintext(
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

        // Committing before return means every envelope handed to transport
        // has already consumed its unique key/index. Ambiguous delivery can
        // retry these immutable bytes but cannot seal new plaintext at index.
        self.sending_chain.install(step.next_chain_key, index + 1);
        Ok(OutboundMessage { index, envelope })
    }

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

    pub fn begin_refresh(&mut self, refresh_id: [u8; 32]) -> SessionResult<RefreshIdDecision> {
        match (self.phase, self.active_refresh_id) {
            (SessionPhase::Established, None) => {
                self.phase = SessionPhase::Refreshing;
                self.active_refresh_id = Some(refresh_id);
                Ok(RefreshIdDecision::Accepted)
            }
            (SessionPhase::Refreshing, Some(active)) if refresh_id < active => {
                self.active_refresh_id = Some(refresh_id);
                Ok(RefreshIdDecision::ReplacedLocal)
            }
            (SessionPhase::Refreshing, Some(active)) if refresh_id == active => {
                Ok(RefreshIdDecision::Accepted)
            }
            (SessionPhase::Refreshing, Some(_)) => Err(SessionError::RefreshConflict),
            _ => Err(SessionError::InvalidState),
        }
    }

    pub fn abort_refresh(&mut self) -> SessionResult<()> {
        if self.phase != SessionPhase::Refreshing {
            return Err(SessionError::InvalidState);
        }
        self.active_refresh_id = None;
        self.phase = SessionPhase::Established;
        Ok(())
    }

    pub fn derive_refresh_candidate(
        &self,
        local_role: RefreshRole,
        refresh_mix: &[u8; 32],
        pretranscript: [u8; 64],
        transcript_hash: [u8; 64],
    ) -> SessionResult<RefreshCandidate> {
        if self.phase != SessionPhase::Refreshing {
            return Err(SessionError::InvalidState);
        }
        derive_refresh_candidate(
            local_role,
            self.session_id,
            &self.refresh_root,
            refresh_mix,
            pretranscript,
            transcript_hash,
        )
    }

    pub fn install_refresh(&mut self, verified: VerifiedRefresh) -> SessionResult<()> {
        if self.phase != SessionPhase::Refreshing {
            return Err(SessionError::InvalidState);
        }
        let (old_id, new_id, transcript, local_role, chain_i2r, chain_r2i, refresh_root) =
            verified.into_parts();
        if old_id != self.session_id {
            return Err(SessionError::InvalidState);
        }
        let (sending_chain, receiving_chain) = match local_role {
            RefreshRole::Initiator => (chain_i2r, chain_r2i),
            RefreshRole::Responder => (chain_r2i, chain_i2r),
        };
        self.session_id = new_id;
        self.transcript_hash = transcript;
        self.refresh_root = refresh_root;
        self.sending_chain = sending_chain;
        self.receiving_chain = receiving_chain;
        self.skipped_keys.clear();
        self.replay.clear();
        self.active_refresh_id = None;
        self.phase = SessionPhase::Established;
        Ok(())
    }

    pub fn full_wipe(&mut self) {
        self.refresh_root = SecretBytes::from_array([0; 32]);
        self.sending_chain = DirectionChain::new(SecretBytes::from_array([0; 32]));
        self.receiving_chain = DirectionChain::new(SecretBytes::from_array([0; 32]));
        self.skipped_keys.clear();
        self.replay.clear();
        self.active_refresh_id = None;
        self.session_id.fill(0);
        self.transcript_hash.fill(0);
        self.phase = SessionPhase::Closed;
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn set_test_send_index(&mut self, index: u64) {
        let key = SecretBytes::from_array(*self.sending_chain.key().expose_secret());
        self.sending_chain.install(key, index);
    }

    #[cfg(test)]
    pub(crate) fn send_invalid_binding_for_test(&mut self) -> SessionResult<OutboundMessage> {
        self.seal_record(
            EnvelopeClass::Lite,
            ProtectedRecord {
                content_kind: ContentKind::Data,
                session_or_group_id: self.session_id,
                sender_id: [1; 32],
                epoch: 0,
                state_version: 0,
                message_index: self.sending_chain.next_index(),
                content: b"invalid binding".to_vec(),
            },
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn seal_test_plaintext(
        &mut self,
        class: EnvelopeClass,
        plaintext: &[u8],
    ) -> SessionResult<OutboundMessage> {
        if plaintext.len() != class.protected_record_size() {
            return Err(SessionError::InvalidPayload);
        }
        let index = self.sending_chain.next_index();
        if index == u64::MAX {
            return Err(SessionError::CounterExhausted);
        }
        let step = derive_step(self.sending_chain.key(), &self.session_id, index)?;
        self.seal_plaintext(class, index, step, plaintext)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn test_state_hash(&self) -> [u8; 32] {
        let mut state = Vec::new();
        state.extend_from_slice(b"HYDRA-MSG/test/session-state");
        state.push(self.role as u8);
        state.push(self.phase as u8);
        state.extend_from_slice(&self.session_id);
        state.extend_from_slice(&self.transcript_hash);
        state.extend_from_slice(&self.local_identity_fingerprint);
        state.extend_from_slice(&self.remote_identity_fingerprint);
        state.extend_from_slice(self.refresh_root.expose_secret());
        state.extend_from_slice(self.sending_chain.key().expose_secret());
        state.extend_from_slice(&self.sending_chain.next_index().to_be_bytes());
        state.extend_from_slice(self.receiving_chain.key().expose_secret());
        state.extend_from_slice(&self.receiving_chain.next_index().to_be_bytes());
        self.skipped_keys.append_test_commitment(&mut state);
        self.replay.append_test_commitment(&mut state);
        match self.active_refresh_id {
            Some(id) => {
                state.push(1);
                state.extend_from_slice(&id);
            }
            None => state.extend_from_slice(&[0; 33]),
        }
        RustCryptoBackend::sha3_256(&state)
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.full_wipe();
    }
}

fn smallest_class(content_length: usize) -> Option<EnvelopeClass> {
    [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ]
    .into_iter()
    .find(|class| content_length <= class.max_content_size())
}

fn smallest_standard_or_full(content_length: usize) -> Option<EnvelopeClass> {
    [EnvelopeClass::Standard, EnvelopeClass::Full]
        .into_iter()
        .find(|class| content_length <= class.max_content_size())
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
        ContentKind::Data => smallest_class(record.content.len()) == Some(class),
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
