use hydra_core::{
    types::{ContentKind, EnvelopeClass, IdentityFingerprint, OuterMode},
    AEAD_NONCE_SIZE, ML_DSA_65_SIG_SIZE, OUTER_HEADER_SIZE, SUITE_ID,
};
use hydra_crypto::{
    CryptoBackend, MlDsaSigningKey, MlDsaVerificationKey, RustCryptoBackend, SecretBytes,
};
use hydra_envelope::{
    decode_outer_header, decode_protected_record, encode_outer_header, encode_protected_record,
    OuterHeader, ProtectedRecord,
};

use crate::{
    lp, u64_be, GroupError, GroupMode, GroupResult, GroupState, MemberId, SenderMessageStep,
};

const LABEL_GROUP_MESSAGE_AEAD: &[u8] = b"HYDRA-MSG/v1/group/message/aead-key";
const LABEL_GROUP_MESSAGE_SIGNATURE: &[u8] = b"HYDRA-MSG/v1/group/message/signature";
const LABEL_IDENTITY_FINGERPRINT: &[u8] = b"HYDRA-MSG/v1/fingerprint";

#[derive(Debug, PartialEq, Eq)]
pub struct GroupOutboundMessage {
    pub sender: MemberId,
    pub index: u64,
    pub envelope: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GroupReceivedMessage {
    pub sender: MemberId,
    pub index: u64,
    pub content: Vec<u8>,
}

impl GroupState {
    pub fn seal_group_data(
        &mut self,
        sender: MemberId,
        content: &[u8],
    ) -> GroupResult<GroupOutboundMessage> {
        self.require_sender(sender)?;
        let class = smallest_class(content.len()).ok_or(GroupError::InvalidEnvelope)?;
        let step = self.next_sender_message_step(sender)?;
        let record = ProtectedRecord {
            content_kind: ContentKind::GroupData,
            session_or_group_id: self.group_id.0,
            sender_id: sender.0,
            epoch: self.epoch.0,
            state_version: self.state_version.0,
            message_index: step.index,
            content: content.to_vec(),
        };
        let plaintext =
            encode_protected_record(class, &record).map_err(|_| GroupError::InvalidEnvelope)?;
        let envelope = seal_group_plaintext(self, class, &step, &plaintext)?;
        Ok(GroupOutboundMessage {
            sender,
            index: step.index,
            envelope,
        })
    }

    pub fn seal_signed_group_data(
        &mut self,
        sender: MemberId,
        signing_key: &MlDsaSigningKey,
        content: &[u8],
    ) -> GroupResult<GroupOutboundMessage> {
        self.require_sender(sender)?;
        let class =
            signed_group_data_class(self.mode, content.len()).ok_or(GroupError::InvalidEnvelope)?;
        let signed_len = signed_group_data_content_len(content.len())?;
        let step = self.next_sender_message_step(sender)?;
        let digest = group_data_signature_digest(self, class, &step, content)?;
        let signature = RustCryptoBackend::mldsa65_sign(signing_key, &digest)
            .map_err(|_| GroupError::InvalidGroupSignature)?;
        let mut signed_content = Vec::with_capacity(signed_len);
        signed_content.extend_from_slice(
            &u32::try_from(content.len())
                .map_err(|_| GroupError::InvalidEnvelope)?
                .to_be_bytes(),
        );
        signed_content.extend_from_slice(content);
        signed_content.extend_from_slice(&signature);
        let record = ProtectedRecord {
            content_kind: ContentKind::GroupData,
            session_or_group_id: self.group_id.0,
            sender_id: sender.0,
            epoch: self.epoch.0,
            state_version: self.state_version.0,
            message_index: step.index,
            content: signed_content,
        };
        let plaintext =
            encode_protected_record(class, &record).map_err(|_| GroupError::InvalidEnvelope)?;
        let envelope = seal_group_plaintext(self, class, &step, &plaintext)?;
        Ok(GroupOutboundMessage {
            sender,
            index: step.index,
            envelope,
        })
    }

    pub fn open_group_data(&mut self, envelope: &[u8]) -> GroupResult<GroupReceivedMessage> {
        self.open_group_data_inner(
            envelope,
            None::<fn(MemberId) -> Option<MlDsaVerificationKey>>,
        )
    }

    pub fn open_signed_group_data<F>(
        &mut self,
        envelope: &[u8],
        verification_key_for: F,
    ) -> GroupResult<GroupReceivedMessage>
    where
        F: FnOnce(MemberId) -> Option<MlDsaVerificationKey>,
    {
        self.open_group_data_inner(envelope, Some(verification_key_for))
    }

    fn open_group_data_inner<F>(
        &mut self,
        envelope: &[u8],
        verification_key_for: Option<F>,
    ) -> GroupResult<GroupReceivedMessage>
    where
        F: FnOnce(MemberId) -> Option<MlDsaVerificationKey>,
    {
        self.require_active()?;
        let header = decode_outer_header(envelope).map_err(|_| GroupError::InvalidEnvelope)?;
        if header.mode != OuterMode::Protected || header.counter == u64::MAX {
            return Err(GroupError::InvalidEnvelope);
        }
        if self
            .replay_state
            .contains_route_tag(header.route_tag, header.counter)
        {
            return Err(GroupError::ReplayDetected);
        }

        let context = self.epoch_key_context();
        let resolution = self.sender_chains.resolution_for_route(
            &context,
            header.route_tag,
            header.counter,
            group_skip_bound(self.mode),
        )?;
        let step = resolution.step();

        let aead_key = group_message_aead_key(self, step)?;
        let plaintext = RustCryptoBackend::aead_open(
            &aead_key,
            &[0_u8; AEAD_NONCE_SIZE],
            &envelope[..OUTER_HEADER_SIZE],
            &envelope[OUTER_HEADER_SIZE..],
        )
        .map_err(|_| GroupError::AuthenticationFailed)?;
        let record = decode_protected_record(header.envelope_class, &plaintext)
            .map_err(|_| GroupError::AuthenticationFailed)?;
        validate_group_data_record(self, &header, step, &record)?;

        let content = if let Some(resolver) = verification_key_for {
            verify_group_data_signature(self, &header, step, &record, resolver)?
        } else {
            record.content
        };

        let mut replay_state = self.replay_state.clone();
        replay_state.mark_accepted(step.sender, step.index, step.route_tag)?;
        let sender = step.sender;
        let index = step.index;
        self.sender_chains
            .commit_resolution(resolution, group_skip_bound(self.mode) as usize)?;
        self.replay_state = replay_state;

        Ok(GroupReceivedMessage {
            sender,
            index,
            content,
        })
    }
}

fn seal_group_plaintext(
    state: &GroupState,
    class: EnvelopeClass,
    step: &SenderMessageStep,
    plaintext: &[u8],
) -> GroupResult<Vec<u8>> {
    let header = encode_outer_header(&OuterHeader::new(
        OuterMode::Protected,
        class,
        step.route_tag,
        step.index,
    ))
    .map_err(|_| GroupError::InvalidEnvelope)?;
    let aead_key = group_message_aead_key(state, step)?;
    let body =
        RustCryptoBackend::aead_seal(&aead_key, &[0_u8; AEAD_NONCE_SIZE], &header, plaintext)
            .map_err(|_| GroupError::AuthenticationFailed)?;
    let mut envelope = Vec::with_capacity(class.envelope_size());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&body);
    Ok(envelope)
}

fn validate_group_data_record(
    state: &GroupState,
    header: &OuterHeader,
    step: &SenderMessageStep,
    record: &ProtectedRecord,
) -> GroupResult<()> {
    if record.content_kind != ContentKind::GroupData
        || record.session_or_group_id != state.group_id.0
        || record.sender_id != step.sender.0
        || record.epoch != state.epoch.0
        || record.state_version != state.state_version.0
        || record.message_index != header.counter
        || record.message_index != step.index
        || !group_data_record_class_allowed(state.mode, record.content.len(), header.envelope_class)
    {
        return Err(GroupError::AuthenticationFailed);
    }
    Ok(())
}

fn verify_group_data_signature<F>(
    state: &GroupState,
    header: &OuterHeader,
    step: &SenderMessageStep,
    record: &ProtectedRecord,
    verification_key_for: F,
) -> GroupResult<Vec<u8>>
where
    F: FnOnce(MemberId) -> Option<MlDsaVerificationKey>,
{
    if record.content.len() < 4 + ML_DSA_65_SIG_SIZE {
        return Err(GroupError::InvalidGroupSignature);
    }
    let application_len = u32::from_be_bytes(
        record.content[..4]
            .try_into()
            .map_err(|_| GroupError::InvalidGroupSignature)?,
    ) as usize;
    let signature_start = 4_usize
        .checked_add(application_len)
        .ok_or(GroupError::InvalidGroupSignature)?;
    let expected_len = signature_start
        .checked_add(ML_DSA_65_SIG_SIZE)
        .ok_or(GroupError::InvalidGroupSignature)?;
    if expected_len != record.content.len()
        || signed_group_data_class(state.mode, application_len) != Some(header.envelope_class)
    {
        return Err(GroupError::InvalidGroupSignature);
    }
    let content = &record.content[4..signature_start];
    let signature = &record.content[signature_start..];
    let verification_key =
        verification_key_for(step.sender).ok_or(GroupError::InvalidGroupSignature)?;
    let fingerprint = identity_fingerprint(&verification_key);
    let roster_entry = state
        .roster
        .iter()
        .find(|entry| entry.member_id == step.sender)
        .ok_or(GroupError::InvalidGroupSignature)?;
    if roster_entry.device_identity_fingerprint != fingerprint {
        return Err(GroupError::InvalidGroupSignature);
    }
    let digest = group_data_signature_digest(state, header.envelope_class, step, content)?;
    RustCryptoBackend::mldsa65_verify(&verification_key, &digest, signature)
        .map_err(|_| GroupError::InvalidGroupSignature)?;
    Ok(content.to_vec())
}

pub fn group_data_signature_digest(
    state: &GroupState,
    class: EnvelopeClass,
    step: &SenderMessageStep,
    content: &[u8],
) -> GroupResult<[u8; 64]> {
    let mut core = Vec::new();
    core.extend_from_slice(&state.group_id.0);
    core.push(state.mode as u8);
    core.push(class as u8);
    core.extend_from_slice(&u64_be(state.epoch.0));
    core.extend_from_slice(&u64_be(state.state_version.0));
    core.extend_from_slice(&state.roster_hash);
    core.extend_from_slice(&state.tree_hash);
    core.extend_from_slice(&state.last_commit_hash);
    core.extend_from_slice(&step.sender.0);
    core.extend_from_slice(&u64_be(step.index));
    core.extend_from_slice(&step.route_tag);
    core.extend_from_slice(&RustCryptoBackend::sha3_512(content));

    let mut input = Vec::new();
    input.extend_from_slice(LABEL_GROUP_MESSAGE_SIGNATURE);
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&lp(&core)?);
    Ok(RustCryptoBackend::sha3_512(&input))
}

pub fn identity_fingerprint(verification_key: &MlDsaVerificationKey) -> IdentityFingerprint {
    let mut input = Vec::new();
    input.extend_from_slice(LABEL_IDENTITY_FINGERPRINT);
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&verification_key.to_bytes());
    IdentityFingerprint(RustCryptoBackend::sha3_256(&input))
}

fn group_message_aead_key(
    state: &GroupState,
    step: &SenderMessageStep,
) -> GroupResult<SecretBytes<32>> {
    let mut context = Vec::new();
    context.extend_from_slice(&SUITE_ID);
    context.extend_from_slice(&state.group_id.0);
    context.push(state.mode as u8);
    context.extend_from_slice(&u64_be(state.epoch.0));
    context.extend_from_slice(&u64_be(state.state_version.0));
    context.extend_from_slice(&step.sender.0);
    context.extend_from_slice(&u64_be(step.index));
    let mut info = Vec::new();
    info.extend_from_slice(&lp(LABEL_GROUP_MESSAGE_AEAD)?);
    info.extend_from_slice(&lp(&context)?);
    let output = RustCryptoBackend::hkdf_expand(step.message_key.expose_for_backend(), &info, 32)
        .map_err(|_| GroupError::AuthenticationFailed)?;
    let key: [u8; 32] = output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::AuthenticationFailed)?;
    Ok(SecretBytes::from_array(key))
}

fn group_data_record_class_allowed(
    mode: GroupMode,
    record_content_len: usize,
    class: EnvelopeClass,
) -> bool {
    match mode {
        GroupMode::Interactive => {
            if record_content_len <= EnvelopeClass::Standard.max_content_size() {
                class == EnvelopeClass::Standard
            } else if record_content_len <= EnvelopeClass::Full.max_content_size() {
                class == EnvelopeClass::Full
            } else {
                false
            }
        }
        GroupMode::Broadcast => smallest_class(record_content_len) == Some(class),
        GroupMode::Lite => {
            class == EnvelopeClass::Lite
                && record_content_len <= EnvelopeClass::Lite.max_content_size()
        }
    }
}

fn signed_group_data_content_len(application_content_len: usize) -> GroupResult<usize> {
    4_usize
        .checked_add(application_content_len)
        .and_then(|len| len.checked_add(ML_DSA_65_SIG_SIZE))
        .ok_or(GroupError::InvalidEnvelope)
}

fn signed_group_data_class(
    mode: GroupMode,
    application_content_len: usize,
) -> Option<EnvelopeClass> {
    let signed_len = signed_group_data_content_len(application_content_len).ok()?;
    match mode {
        GroupMode::Lite => {
            if application_content_len <= 607
                && signed_len <= EnvelopeClass::Lite.max_content_size()
            {
                Some(EnvelopeClass::Lite)
            } else {
                None
            }
        }
        GroupMode::Interactive => {
            if signed_len <= EnvelopeClass::Standard.max_content_size() {
                Some(EnvelopeClass::Standard)
            } else if signed_len <= EnvelopeClass::Full.max_content_size() {
                Some(EnvelopeClass::Full)
            } else {
                None
            }
        }
        GroupMode::Broadcast => smallest_class(signed_len),
    }
}

fn group_skip_bound(mode: GroupMode) -> u64 {
    match mode {
        GroupMode::Lite => 32,
        GroupMode::Interactive => 64,
        GroupMode::Broadcast => 256,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GovernancePolicy, GroupMode, GroupRole, MemberStatus, MembershipMechanism, ModePolicy,
        RosterEntry, StateVersion,
    };
    use hydra_core::types::{Epoch, GroupId, IdentityFingerprint, Secret32};

    fn member(value: u8) -> MemberId {
        MemberId([value; 32])
    }

    fn fingerprint(value: u8) -> IdentityFingerprint {
        IdentityFingerprint([value; 32])
    }

    fn active_entry(member_value: u8, role: GroupRole) -> RosterEntry {
        RosterEntry {
            member_id: member(member_value),
            device_identity_fingerprint: fingerprint(member_value),
            role,
            status: MemberStatus::Active,
            tree_leaf_slot: u32::from(member_value),
            joined_epoch: Epoch(1),
            removed_epoch: Epoch(0),
        }
    }

    fn signed_entry(member_value: u8, role: GroupRole, key: &MlDsaVerificationKey) -> RosterEntry {
        RosterEntry {
            device_identity_fingerprint: identity_fingerprint(key),
            ..active_entry(member_value, role)
        }
    }

    fn lite_state() -> GroupState {
        let roster = vec![
            active_entry(1, GroupRole::Member),
            active_entry(2, GroupRole::Member),
        ];
        build_lite_state(roster)
    }

    fn signed_lite_state(key: &MlDsaVerificationKey) -> GroupState {
        build_lite_state(vec![
            signed_entry(1, GroupRole::Member, key),
            active_entry(2, GroupRole::Member),
        ])
    }

    fn build_lite_state(roster: Vec<RosterEntry>) -> GroupState {
        let mut state = GroupState::new_validated(crate::GroupStateConfig {
            group_id: GroupId([0x42; 32]),
            mode: GroupMode::Lite,
            mechanism: MembershipMechanism::DirectWrap,
            epoch: Epoch(7),
            state_version: StateVersion(9),
            governance_policy: GovernancePolicy::single_signer(member(1)),
            mode_policy: ModePolicy::default(),
            roster,
        })
        .unwrap();
        state.tree_hash = [0x77; 64];
        state.last_commit_hash = [0x88; 64];
        state
            .install_epoch_sender_chains(&Secret32::new([0x33; 32]))
            .unwrap();
        state
    }

    #[test]
    fn group_data_seals_opens_and_advances_one_sender_chain() {
        let mut sender = lite_state();
        let mut receiver = lite_state();
        let before_sender_two = receiver.sender_chains.next_index(member(2));
        let outbound = sender.seal_group_data(member(1), b"group hello").unwrap();
        assert_eq!(outbound.index, 0);
        assert_eq!(sender.sender_chains.next_index(member(1)), Some(1));

        let received = receiver.open_group_data(&outbound.envelope).unwrap();
        assert_eq!(received.sender, member(1));
        assert_eq!(received.index, 0);
        assert_eq!(received.content, b"group hello");
        assert_eq!(receiver.sender_chains.next_index(member(1)), Some(1));
        assert_eq!(
            receiver.sender_chains.next_index(member(2)),
            before_sender_two
        );
    }

    #[test]
    fn signed_group_data_verifies_signature_and_strips_it_from_content() {
        let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
        let mut sender = signed_lite_state(&keypair.verification_key);
        let mut receiver = signed_lite_state(&keypair.verification_key);
        let outbound = sender
            .seal_signed_group_data(member(1), &keypair.signing_key, b"signed group hello")
            .unwrap();
        let received = receiver
            .open_signed_group_data(&outbound.envelope, |sender| {
                if sender == member(1) {
                    Some(keypair.verification_key.clone())
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(received.sender, member(1));
        assert_eq!(received.content, b"signed group hello");
    }

    #[test]
    fn invalid_group_sender_signature_preserves_receiver_state() {
        let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
        let wrong = RustCryptoBackend::mldsa65_generate().unwrap();
        let mut sender = signed_lite_state(&keypair.verification_key);
        let mut receiver = signed_lite_state(&keypair.verification_key);
        let outbound = sender
            .seal_signed_group_data(member(1), &keypair.signing_key, b"signed group hello")
            .unwrap();
        let before_index = receiver.sender_chains.next_index(member(1));
        let before_commitment = receiver.sender_chains.chain_key_commitment(member(1));
        let before_replay = receiver.replay_state.accepted_messages.len();
        assert_eq!(
            receiver.open_signed_group_data(&outbound.envelope, |_| {
                Some(wrong.verification_key.clone())
            }),
            Err(GroupError::InvalidGroupSignature)
        );
        assert_eq!(receiver.sender_chains.next_index(member(1)), before_index);
        assert_eq!(
            receiver.sender_chains.chain_key_commitment(member(1)),
            before_commitment
        );
        assert_eq!(receiver.replay_state.accepted_messages.len(), before_replay);
    }

    #[test]
    fn group_signature_digest_binds_mode_and_envelope_class() {
        let keypair = RustCryptoBackend::mldsa65_generate().unwrap();
        let mut state = signed_lite_state(&keypair.verification_key);
        let step = state.next_sender_message_step(member(1)).unwrap();
        let lite = group_data_signature_digest(&state, EnvelopeClass::Lite, &step, b"x").unwrap();
        let standard =
            group_data_signature_digest(&state, EnvelopeClass::Standard, &step, b"x").unwrap();
        assert_ne!(lite, standard);
        let mut broadcast = state;
        broadcast.mode = GroupMode::Broadcast;
        let broadcast_digest =
            group_data_signature_digest(&broadcast, EnvelopeClass::Lite, &step, b"x").unwrap();
        assert_ne!(lite, broadcast_digest);
    }

    #[test]
    fn duplicate_group_data_is_rejected_without_advancing_again() {
        let mut sender = lite_state();
        let mut receiver = lite_state();
        let outbound = sender.seal_group_data(member(1), b"duplicate").unwrap();
        receiver.open_group_data(&outbound.envelope).unwrap();
        let before = receiver.sender_chains.chain_key_commitment(member(1));
        assert_eq!(
            receiver.open_group_data(&outbound.envelope),
            Err(GroupError::ReplayDetected)
        );
        assert_eq!(
            receiver.sender_chains.chain_key_commitment(member(1)),
            before
        );
    }

    #[test]
    fn authentication_failure_preserves_receiver_chain_and_replay_state() {
        let mut sender = lite_state();
        let mut receiver = lite_state();
        let mut outbound = sender.seal_group_data(member(1), b"tamper").unwrap();
        outbound.envelope[100] ^= 1;
        let before_index = receiver.sender_chains.next_index(member(1));
        let before_commitment = receiver.sender_chains.chain_key_commitment(member(1));
        let before_replay = receiver.replay_state.accepted_messages.len();
        assert_eq!(
            receiver.open_group_data(&outbound.envelope),
            Err(GroupError::AuthenticationFailed)
        );
        assert_eq!(receiver.sender_chains.next_index(member(1)), before_index);
        assert_eq!(
            receiver.sender_chains.chain_key_commitment(member(1)),
            before_commitment
        );
        assert_eq!(receiver.replay_state.accepted_messages.len(), before_replay);
    }

    #[test]
    fn sender_must_be_send_capable_and_epoch_installed() {
        let mut state = lite_state();
        state.sender_chains.clear();
        assert_eq!(
            state.seal_group_data(member(1), b"not installed"),
            Err(GroupError::SenderNotAllowed {
                member_id: member(1)
            })
        );

        let roster = vec![
            active_entry(1, GroupRole::Moderator),
            active_entry(2, GroupRole::Audience),
        ];
        let mut broadcast = GroupState::new_validated(crate::GroupStateConfig {
            group_id: GroupId([0x99; 32]),
            mode: GroupMode::Broadcast,
            mechanism: MembershipMechanism::TreeKem,
            epoch: Epoch(1),
            state_version: StateVersion(0),
            governance_policy: GovernancePolicy::single_signer(member(1)),
            mode_policy: ModePolicy::default(),
            roster,
        })
        .unwrap();
        broadcast.tree_hash = [0x11; 64];
        broadcast.last_commit_hash = [0x22; 64];
        broadcast
            .install_epoch_sender_chains(&Secret32::new([0x44; 32]))
            .unwrap();
        assert_eq!(
            broadcast.seal_group_data(member(2), b"audience"),
            Err(GroupError::SenderNotAllowed {
                member_id: member(2)
            })
        );
    }

    #[test]
    fn class_boundaries_select_smallest_group_data_class() {
        let mut sender = lite_state();
        for (length, expected) in [
            (hydra_core::LITE_MAX_CONTENT_SIZE, EnvelopeClass::Lite),
            (
                hydra_core::LITE_MAX_CONTENT_SIZE + 1,
                EnvelopeClass::Standard,
            ),
            (
                hydra_core::STANDARD_MAX_CONTENT_SIZE + 1,
                EnvelopeClass::Full,
            ),
        ] {
            let outbound = sender
                .seal_group_data(member(1), &vec![0xa5; length])
                .unwrap();
            let header = decode_outer_header(&outbound.envelope).unwrap();
            assert_eq!(header.envelope_class, expected);
        }
        assert_eq!(
            sender.seal_group_data(member(1), &vec![0; hydra_core::FULL_MAX_CONTENT_SIZE + 1]),
            Err(GroupError::InvalidEnvelope)
        );
    }
}
