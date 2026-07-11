use hydra_core::types::{ContentKind, OuterMode};
use hydra_crypto::MlDsaVerificationKey;
use hydra_envelope::{decode_outer_header, decode_protected_record, OuterHeader, ProtectedRecord};

use crate::{GroupError, GroupResult, GroupState, MemberId, SenderMessageStep};

use super::{
    crypto::open_group_ciphertext,
    signature::verify_group_data_signature,
    sizing::{group_data_record_class_allowed, group_skip_bound},
    GroupReceivedMessage,
};

impl GroupState {
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

        let plaintext = open_group_ciphertext(self, step, envelope)?;
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
