use crate::{
    limits::{
        reject_encoded_size, MAX_HANDSHAKE_ANSWER_BYTES, MAX_HANDSHAKE_FINISH_BYTES,
        MAX_HANDSHAKE_OFFER_BYTES,
    },
    HydraMsgError, HydraResult, IdentityId,
};
use hydra_core::{
    types::{ContentKind, EnvelopeClass, OuterMode},
    ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE, ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE,
    OUTER_HEADER_SIZE, PROTOCOL_VERSION, SUITE_ID, TRANSCRIPT_HASH_SIZE, X25519_SIZE,
};
use hydra_crypto::{
    CryptoBackend, MlDsaSigningKey, MlDsaVerificationKey, RustCryptoBackend, SecretBytes,
};
use hydra_envelope::{
    decode_outer_header, decode_protected_record, encode_outer_header, encode_protected_record,
    OuterHeader, ProtectedRecord,
};

const INIT_CORE_SIZE: usize = 3_249;
const RESP_CORE_SIZE: usize = 3_217;
const BOOTSTRAP_CONTROL_LEN_SIZE: usize = 4;
const FINISH_CONTENT_SIZE: usize = 96; // v1: 64-byte transcript hash + 32-byte session id

#[derive(Clone)]
pub(crate) struct ParsedHandshakeOffer {
    pub(crate) peer_id: IdentityId,
    pub(crate) initiator_fingerprint: [u8; 32],
    pub(crate) expected_responder_fingerprint: [u8; 32],
    pub(crate) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) nonce: [u8; 32],
    pub(crate) x25519_public: [u8; X25519_SIZE],
    pub(crate) kem_public_key: [u8; ML_KEM_768_EK_SIZE],
    pub(crate) signature: [u8; ML_DSA_65_SIG_SIZE],
    pub(crate) core: Vec<u8>,
    pub(crate) init_hash: [u8; TRANSCRIPT_HASH_SIZE],
}

#[derive(Clone)]
pub(crate) struct ParsedHandshakeAnswer {
    pub(crate) peer_id: IdentityId,
    pub(crate) responder_fingerprint: [u8; 32],
    pub(crate) initiator_fingerprint: [u8; 32],
    pub(crate) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) init_hash: [u8; TRANSCRIPT_HASH_SIZE],
    pub(crate) x25519_public: [u8; X25519_SIZE],
    pub(crate) kem_ciphertext: [u8; ML_KEM_768_CT_SIZE],
    pub(crate) signature: [u8; ML_DSA_65_SIG_SIZE],
    pub(crate) confirmation_tag: [u8; 32],
    pub(crate) core: Vec<u8>,
}

pub(crate) struct HandshakeMaterial {
    pub(crate) handshake_secret: SecretBytes<32>,
    pub(crate) transcript_hash: [u8; TRANSCRIPT_HASH_SIZE],
    pub(crate) session_id: [u8; 32],
    pub(crate) finish_key: SecretBytes<32>,
}

pub(crate) struct HandshakeAnswerParts<'a> {
    pub(crate) public_key: &'a [u8; ML_DSA_65_VK_SIZE],
    pub(crate) nonce: [u8; 32],
    pub(crate) x25519_public: [u8; X25519_SIZE],
    pub(crate) kem_ciphertext: &'a [u8; ML_KEM_768_CT_SIZE],
    pub(crate) offer: &'a ParsedHandshakeOffer,
    pub(crate) signing_key: &'a MlDsaSigningKey,
    pub(crate) x25519_secret: &'a SecretBytes<32>,
    pub(crate) kem_secret: &'a SecretBytes<32>,
}

pub(crate) fn identity_fingerprint(public_key: &[u8; ML_DSA_65_VK_SIZE]) -> [u8; 32] {
    let mut input = Vec::with_capacity(27 + SUITE_ID.len() + public_key.len());
    input.extend_from_slice(b"HYDRA-MSG/v1/fingerprint");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(public_key);
    RustCryptoBackend::sha3_256(&input)
}

pub(crate) fn encode_handshake_offer(
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
    expected_responder_fingerprint: [u8; 32],
    x25519_public: [u8; X25519_SIZE],
    kem_public_key: &[u8; ML_KEM_768_EK_SIZE],
    signing_key: &MlDsaSigningKey,
    route_tag: [u8; 16],
) -> HydraResult<Vec<u8>> {
    let core = encode_offer_core(
        nonce,
        expected_responder_fingerprint,
        public_key,
        x25519_public,
        kem_public_key,
    );
    let signature = RustCryptoBackend::mldsa65_sign(signing_key, &offer_signature_digest(&core))?;
    encode_bootstrap(
        OuterMode::BootstrapInit,
        route_tag,
        &core,
        &signature,
        &[0; 32],
    )
}

pub(crate) fn encode_handshake_answer(
    parts: HandshakeAnswerParts<'_>,
    route_tag: [u8; 16],
) -> HydraResult<(Vec<u8>, HandshakeMaterial)> {
    let core = encode_answer_core(
        parts.offer.init_hash,
        parts.nonce,
        parts.offer.initiator_fingerprint,
        parts.public_key,
        parts.x25519_public,
        parts.kem_ciphertext,
    );
    let signature = RustCryptoBackend::mldsa65_sign(
        parts.signing_key,
        &answer_signature_digest(parts.offer.init_hash, &core),
    )?;
    let material = derive_material_from_parts(
        parts.offer,
        &core,
        &signature,
        parts.x25519_secret,
        parts.kem_secret,
    );
    let confirmation_tag = response_confirmation(&material);
    let encoded = encode_bootstrap(
        OuterMode::BootstrapResp,
        route_tag,
        &core,
        &signature,
        &confirmation_tag,
    )?;
    Ok((encoded, material))
}

pub(crate) fn decode_handshake_offer(bytes: &[u8]) -> HydraResult<ParsedHandshakeOffer> {
    reject_encoded_size(
        bytes.len(),
        MAX_HANDSHAKE_OFFER_BYTES,
        "handshake INIT size",
    )?;
    let (core, signature, authenticator) =
        decode_bootstrap(bytes, OuterMode::BootstrapInit, INIT_CORE_SIZE)?;
    if authenticator != [0; 32] {
        return Err(HydraMsgError::InvalidEncoding(
            "INIT authenticator must be zero",
        ));
    }
    let mut at = 0usize;
    require_byte(&core, &mut at, PROTOCOL_VERSION, "INIT protocol version")?;
    require_slice(&core, &mut at, &SUITE_ID, "INIT suite")?;
    let nonce = take_array::<32>(&core, &mut at, "INIT nonce")?;
    let expected_responder_fingerprint =
        take_array::<32>(&core, &mut at, "INIT expected responder fingerprint")?;
    let public_key = take_array::<ML_DSA_65_VK_SIZE>(&core, &mut at, "INIT verification key")?;
    let x25519_public = take_array::<X25519_SIZE>(&core, &mut at, "INIT X25519 key")?;
    let kem_public_key = take_array::<ML_KEM_768_EK_SIZE>(&core, &mut at, "INIT ML-KEM key")?;
    if at != core.len() {
        return Err(HydraMsgError::InvalidEncoding("INIT core length"));
    }
    let verifying_key = MlDsaVerificationKey::from_bytes(&public_key)?;
    RustCryptoBackend::mldsa65_verify(&verifying_key, &offer_signature_digest(&core), &signature)?;
    let initiator_fingerprint = identity_fingerprint(&public_key);
    let init_hash = init_hash(&core, &signature);
    Ok(ParsedHandshakeOffer {
        peer_id: IdentityId(RustCryptoBackend::sha3_256(&public_key)),
        initiator_fingerprint,
        expected_responder_fingerprint,
        public_key,
        nonce,
        x25519_public,
        kem_public_key,
        signature,
        core,
        init_hash,
    })
}

pub(crate) fn decode_handshake_answer(bytes: &[u8]) -> HydraResult<ParsedHandshakeAnswer> {
    reject_encoded_size(
        bytes.len(),
        MAX_HANDSHAKE_ANSWER_BYTES,
        "handshake RESP size",
    )?;
    let (core, signature, confirmation_tag) =
        decode_bootstrap(bytes, OuterMode::BootstrapResp, RESP_CORE_SIZE)?;
    let mut at = 0usize;
    require_byte(&core, &mut at, PROTOCOL_VERSION, "RESP protocol version")?;
    require_slice(&core, &mut at, &SUITE_ID, "RESP suite")?;
    let init_hash = take_array::<TRANSCRIPT_HASH_SIZE>(&core, &mut at, "RESP init hash")?;
    let _nonce = take_array::<32>(&core, &mut at, "RESP nonce")?;
    let initiator_fingerprint = take_array::<32>(&core, &mut at, "RESP initiator fingerprint")?;
    let public_key = take_array::<ML_DSA_65_VK_SIZE>(&core, &mut at, "RESP verification key")?;
    let x25519_public = take_array::<X25519_SIZE>(&core, &mut at, "RESP X25519 key")?;
    let kem_ciphertext =
        take_array::<ML_KEM_768_CT_SIZE>(&core, &mut at, "RESP ML-KEM ciphertext")?;
    if at != core.len() {
        return Err(HydraMsgError::InvalidEncoding("RESP core length"));
    }
    Ok(ParsedHandshakeAnswer {
        peer_id: IdentityId(RustCryptoBackend::sha3_256(&public_key)),
        responder_fingerprint: identity_fingerprint(&public_key),
        initiator_fingerprint,
        public_key,
        init_hash,
        x25519_public,
        kem_ciphertext,
        signature,
        confirmation_tag,
        core,
    })
}

pub(crate) fn verify_answer_and_derive(
    answer: &ParsedHandshakeAnswer,
    offer: &ParsedHandshakeOffer,
    x25519_secret: &SecretBytes<32>,
    kem_secret: &SecretBytes<32>,
) -> HydraResult<HandshakeMaterial> {
    if answer.init_hash != offer.init_hash {
        return Err(HydraMsgError::InvalidEncoding("RESP does not match INIT"));
    }
    if answer.initiator_fingerprint != offer.initiator_fingerprint {
        return Err(HydraMsgError::InvalidEncoding(
            "RESP initiator fingerprint mismatch",
        ));
    }
    if answer.responder_fingerprint != offer.expected_responder_fingerprint {
        return Err(HydraMsgError::InvalidEncoding(
            "RESP responder fingerprint mismatch",
        ));
    }
    let verifying_key = MlDsaVerificationKey::from_bytes(&answer.public_key)?;
    let signature_digest = answer_signature_digest(answer.init_hash, &answer.core);
    RustCryptoBackend::mldsa65_verify(&verifying_key, &signature_digest, &answer.signature)?;
    let core = answer.core.as_slice();
    let signature = &answer.signature;
    let material = derive_material_from_parts(offer, core, signature, x25519_secret, kem_secret);
    let confirm_key = derive_expand32(
        &material.handshake_secret,
        b"HYDRA-MSG/v1/confirm-key",
        &material.transcript_hash,
    );
    let confirmation = confirmation_input(&material.transcript_hash, &material.session_id);
    RustCryptoBackend::verify_hmac_sha3_256(
        &confirm_key,
        &confirmation,
        &answer.confirmation_tag,
    )?;
    Ok(material)
}

pub(crate) fn encode_handshake_finish(material: &HandshakeMaterial) -> HydraResult<Vec<u8>> {
    let route_tag = finish_route_tag(material);
    let header = encode_outer_header(&OuterHeader::new(
        OuterMode::Protected,
        EnvelopeClass::Lite,
        route_tag,
        0,
    ))
    .map_err(|_| HydraMsgError::InvalidEncoding("FINISH outer header"))?;
    let mut content = Vec::with_capacity(FINISH_CONTENT_SIZE);
    content.extend_from_slice(&material.transcript_hash);
    content.extend_from_slice(&material.session_id);
    let plaintext = encode_protected_record(
        EnvelopeClass::Lite,
        &ProtectedRecord {
            content_kind: ContentKind::HandshakeFinish,
            session_or_group_id: material.session_id,
            sender_id: [0; 32],
            epoch: 0,
            state_version: 0,
            message_index: 0,
            content,
        },
    )
    .map_err(|_| HydraMsgError::InvalidEncoding("FINISH protected record"))?;
    let body = RustCryptoBackend::aead_seal(&material.finish_key, &[0; 12], &header, &plaintext)?;
    let mut envelope = Vec::with_capacity(EnvelopeClass::Lite.envelope_size());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&body);
    Ok(envelope)
}

pub(crate) fn verify_handshake_finish(
    finish: &[u8],
    material: &HandshakeMaterial,
) -> HydraResult<()> {
    reject_encoded_size(
        finish.len(),
        MAX_HANDSHAKE_FINISH_BYTES,
        "handshake FINISH size",
    )?;
    if finish.len() != EnvelopeClass::Lite.envelope_size() {
        return Err(HydraMsgError::InvalidEncoding("FINISH envelope size"));
    }
    let header = decode_outer_header(finish)
        .map_err(|_| HydraMsgError::InvalidEncoding("FINISH outer header"))?;
    if !handshake_finish_header_matches(&header, material) {
        return Err(HydraMsgError::InvalidEncoding("FINISH header mismatch"));
    }
    let plaintext = RustCryptoBackend::aead_open(
        &material.finish_key,
        &[0; 12],
        &finish[..OUTER_HEADER_SIZE],
        &finish[OUTER_HEADER_SIZE..],
    )?;
    let record = decode_protected_record(EnvelopeClass::Lite, &plaintext)
        .map_err(|_| HydraMsgError::InvalidEncoding("FINISH protected record"))?;
    let mut expected = Vec::with_capacity(FINISH_CONTENT_SIZE);
    expected.extend_from_slice(&material.transcript_hash);
    expected.extend_from_slice(&material.session_id);
    if !handshake_finish_record_matches(&record, material, &expected) {
        return Err(HydraMsgError::InvalidEncoding(
            "FINISH transcript/session mismatch",
        ));
    }
    Ok(())
}

fn handshake_finish_header_matches(header: &OuterHeader, material: &HandshakeMaterial) -> bool {
    header.mode == OuterMode::Protected
        && header.envelope_class == EnvelopeClass::Lite
        && header.counter == 0
        && header.route_tag == finish_route_tag(material)
}

fn handshake_finish_record_matches(
    record: &ProtectedRecord,
    material: &HandshakeMaterial,
    expected: &[u8],
) -> bool {
    record.content_kind == ContentKind::HandshakeFinish
        && record.session_or_group_id == material.session_id
        && record.sender_id == [0; 32]
        && record.epoch == 0
        && record.state_version == 0
        && record.message_index == 0
        && record.content == expected
}

pub(crate) fn finish_route_tag(material: &HandshakeMaterial) -> [u8; 16] {
    let mut input = Vec::with_capacity(24 + 32 + TRANSCRIPT_HASH_SIZE);
    input.extend_from_slice(b"HYDRA-MSG/v1/route-tag");
    input.extend_from_slice(&material.session_id);
    input.extend_from_slice(&material.transcript_hash);
    let full = RustCryptoBackend::hmac_sha3_256(&material.finish_key, &input);
    full[..16].try_into().expect("route tag has fixed length")
}

mod wire;
use wire::*;
