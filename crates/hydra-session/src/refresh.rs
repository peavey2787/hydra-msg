use hydra_core::{
    types::{ContentKind, EnvelopeClass, OuterMode},
    OUTER_HEADER_SIZE,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use hydra_envelope::{
    decode_outer_header, decode_protected_record, encode_outer_header, encode_protected_record,
    OuterHeader, ProtectedRecord,
};

use crate::{
    key_derivation::expand32,
    ratchet::{constant_time_tag_eq, DirectionChain},
    SessionError, SessionResult,
};

pub struct RefreshCandidate {
    local_role: RefreshRole,
    old_session_id: [u8; 32],
    new_session_id: [u8; 32],
    pretranscript: [u8; 64],
    transcript_hash: [u8; 64],
    chain_i2r: SecretBytes<32>,
    chain_r2i: SecretBytes<32>,
    refresh_root: SecretBytes<32>,
    confirm_key: SecretBytes<32>,
    finish_key: SecretBytes<32>,
}

pub struct ConfirmedRefresh(RefreshCandidate);
pub struct VerifiedRefresh(pub(crate) RefreshCandidate);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshRole {
    Initiator,
    Responder,
}

pub fn derive_refresh_candidate(
    local_role: RefreshRole,
    old_session_id: [u8; 32],
    old_refresh_root: &SecretBytes<32>,
    refresh_mix: &[u8; 32],
    pretranscript: [u8; 64],
    transcript_hash: [u8; 64],
) -> SessionResult<RefreshCandidate> {
    // `refresh_mix` is accepted only after the caller has verified the signed
    // X25519+ML-KEM refresh transcript. This state layer never treats an
    // unauthenticated component as sufficient for cutover.
    let candidate_secret =
        RustCryptoBackend::hkdf_extract(old_refresh_root.expose_secret(), refresh_mix);
    let new_session_id = *expand32(
        &candidate_secret,
        b"HYDRA-MSG/v1/session-id",
        &pretranscript,
    )?
    .expose_secret();
    Ok(RefreshCandidate {
        local_role,
        old_session_id,
        new_session_id,
        pretranscript,
        transcript_hash,
        chain_i2r: expand32(
            &candidate_secret,
            b"HYDRA-MSG/v1/init-chain/i2r",
            &transcript_hash,
        )?,
        chain_r2i: expand32(
            &candidate_secret,
            b"HYDRA-MSG/v1/init-chain/r2i",
            &transcript_hash,
        )?,
        refresh_root: expand32(
            &candidate_secret,
            b"HYDRA-MSG/v1/refresh-root",
            &transcript_hash,
        )?,
        confirm_key: expand32(
            &candidate_secret,
            b"HYDRA-MSG/v1/confirm-key",
            &pretranscript,
        )?,
        finish_key: expand32(
            &candidate_secret,
            b"HYDRA-MSG/v1/finish-key",
            &transcript_hash,
        )?,
    })
}

impl RefreshCandidate {
    #[must_use]
    pub const fn new_session_id(&self) -> &[u8; 32] {
        &self.new_session_id
    }

    #[must_use]
    pub fn response_confirmation(&self) -> [u8; 32] {
        let mut input = Vec::new();
        input.extend_from_slice(b"HYDRA-MSG/v1/resp-confirm");
        input.extend_from_slice(&self.pretranscript);
        input.extend_from_slice(&self.new_session_id);
        RustCryptoBackend::hmac_sha3_256(&self.confirm_key, &input)
    }

    pub fn confirm_response(self, expected: &[u8]) -> SessionResult<ConfirmedRefresh> {
        let mut input = Vec::new();
        input.extend_from_slice(b"HYDRA-MSG/v1/resp-confirm");
        input.extend_from_slice(&self.pretranscript);
        input.extend_from_slice(&self.new_session_id);
        RustCryptoBackend::verify_hmac_sha3_256(&self.confirm_key, &input, expected)
            .map_err(|_| SessionError::AuthenticationFailed)?;
        Ok(ConfirmedRefresh(self))
    }
}

impl ConfirmedRefresh {
    fn route_tag(&self) -> [u8; 16] {
        let mut input = Vec::new();
        input.extend_from_slice(b"HYDRA-MSG/v1/route-tag");
        input.extend_from_slice(&self.0.new_session_id);
        input.extend_from_slice(&self.0.transcript_hash);
        let full = RustCryptoBackend::hmac_sha3_256(&self.0.finish_key, &input);
        full[..16].try_into().expect("route tag has fixed length")
    }

    fn plaintext(&self) -> SessionResult<Vec<u8>> {
        let mut content = Vec::with_capacity(96);
        content.extend_from_slice(&self.0.transcript_hash);
        content.extend_from_slice(&self.0.new_session_id);
        encode_protected_record(
            EnvelopeClass::Lite,
            &ProtectedRecord {
                content_kind: ContentKind::RefreshFinish,
                session_or_group_id: self.0.new_session_id,
                sender_id: [0; 32],
                epoch: 0,
                state_version: 0,
                message_index: 0,
                content,
            },
        )
        .map_err(|_| SessionError::InvalidPayload)
    }

    pub fn seal_finish(self) -> SessionResult<(Vec<u8>, VerifiedRefresh)> {
        let header = encode_outer_header(&OuterHeader::new(
            OuterMode::Protected,
            EnvelopeClass::Lite,
            self.route_tag(),
            0,
        ))
        .map_err(|_| SessionError::InvalidEnvelope)?;
        let plaintext = self.plaintext()?;
        let body =
            RustCryptoBackend::aead_seal(&self.0.finish_key, &[0_u8; 12], &header, &plaintext)
                .map_err(|_| SessionError::AuthenticationFailed)?;
        let mut envelope = Vec::with_capacity(EnvelopeClass::Lite.envelope_size());
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&body);
        Ok((envelope, VerifiedRefresh(self.0)))
    }

    pub fn open_finish(self, envelope: &[u8]) -> SessionResult<VerifiedRefresh> {
        let header = decode_outer_header(envelope).map_err(|_| SessionError::InvalidEnvelope)?;
        if header.mode != OuterMode::Protected
            || header.envelope_class != EnvelopeClass::Lite
            || header.counter != 0
            || !constant_time_tag_eq(&header.route_tag, &self.route_tag())
        {
            return Err(SessionError::AuthenticationFailed);
        }
        let plaintext = RustCryptoBackend::aead_open(
            &self.0.finish_key,
            &[0_u8; 12],
            &envelope[..OUTER_HEADER_SIZE],
            &envelope[OUTER_HEADER_SIZE..],
        )
        .map_err(|_| SessionError::AuthenticationFailed)?;
        let record = decode_protected_record(EnvelopeClass::Lite, &plaintext)
            .map_err(|_| SessionError::AuthenticationFailed)?;
        let mut expected_content = Vec::with_capacity(96);
        expected_content.extend_from_slice(&self.0.transcript_hash);
        expected_content.extend_from_slice(&self.0.new_session_id);
        if record.content_kind != ContentKind::RefreshFinish
            || record.session_or_group_id != self.0.new_session_id
            || record.sender_id != [0; 32]
            || record.epoch != 0
            || record.state_version != 0
            || record.message_index != 0
            || record.content != expected_content
        {
            return Err(SessionError::AuthenticationFailed);
        }
        Ok(VerifiedRefresh(self.0))
    }
}

impl VerifiedRefresh {
    pub(crate) fn into_parts(
        self,
    ) -> (
        [u8; 32],
        [u8; 32],
        [u8; 64],
        RefreshRole,
        DirectionChain,
        DirectionChain,
        SecretBytes<32>,
    ) {
        (
            self.0.old_session_id,
            self.0.new_session_id,
            self.0.transcript_hash,
            self.0.local_role,
            DirectionChain::new(self.0.chain_i2r),
            DirectionChain::new(self.0.chain_r2i),
            self.0.refresh_root,
        )
    }
}
