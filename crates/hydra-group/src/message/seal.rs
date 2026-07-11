use hydra_core::types::ContentKind;
use hydra_crypto::{CryptoBackend, MlDsaSigningKey, RustCryptoBackend};
use hydra_envelope::{encode_protected_record, ProtectedRecord};

use crate::{GroupError, GroupResult, GroupState, MemberId};

use super::{
    crypto::seal_group_plaintext,
    signature::group_data_signature_digest,
    sizing::{signed_group_data_class, signed_group_data_content_len, smallest_class},
    GroupOutboundMessage,
};

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
}
