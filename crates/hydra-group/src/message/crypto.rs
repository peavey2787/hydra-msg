use hydra_core::{
    types::{EnvelopeClass, OuterMode},
    AEAD_NONCE_SIZE, OUTER_HEADER_SIZE, SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_envelope::{encode_outer_header, OuterHeader};

use crate::{lp, u64_be, GroupError, GroupResult, GroupState, SenderMessageStep};

const LABEL_GROUP_MESSAGE_AEAD: &[u8] = b"HYDRA-MSG/v1/group/message/aead-key";

pub(super) fn seal_group_plaintext(
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

pub(super) fn open_group_ciphertext(
    state: &GroupState,
    step: &SenderMessageStep,
    envelope: &[u8],
) -> GroupResult<Vec<u8>> {
    let aead_key = group_message_aead_key(state, step)?;
    let plaintext = RustCryptoBackend::aead_open(
        &aead_key,
        &[0_u8; AEAD_NONCE_SIZE],
        &envelope[..OUTER_HEADER_SIZE],
        &envelope[OUTER_HEADER_SIZE..],
    )
    .map_err(|_| GroupError::AuthenticationFailed)?;
    Ok((*plaintext).clone())
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
