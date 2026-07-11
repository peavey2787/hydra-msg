use hydra_core::{
    types::{EnvelopeClass, IdentityFingerprint},
    ML_DSA_65_SIG_SIZE, SUITE_ID,
};
use hydra_crypto::{CryptoBackend, MlDsaVerificationKey, RustCryptoBackend};
use hydra_envelope::{OuterHeader, ProtectedRecord};

use crate::{lp, u64_be, GroupError, GroupResult, GroupState, MemberId, SenderMessageStep};

use super::sizing::signed_group_data_class;

const LABEL_GROUP_MESSAGE_SIGNATURE: &[u8] = b"HYDRA-MSG/v1/group/message/signature";
const LABEL_IDENTITY_FINGERPRINT: &[u8] = b"HYDRA-MSG/v1/fingerprint";

pub(super) fn verify_group_data_signature<F>(
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
