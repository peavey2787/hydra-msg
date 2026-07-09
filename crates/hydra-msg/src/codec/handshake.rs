use super::{handshake_fields::parse_fields, hex_encode};
use crate::{HydraMsgError, HydraResult, IdentityId, ANSWER_MAGIC, OFFER_MAGIC};
use hydra_core::{
    ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE, ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE,
    TRANSCRIPT_HASH_SIZE, X25519_SIZE,
};
use hydra_crypto::{
    CryptoBackend, MlDsaSigningKey, MlDsaVerificationKey, RustCryptoBackend, SecretBytes,
};

#[derive(Clone)]
pub(crate) struct ParsedHandshakeOffer {
    pub(crate) peer_id: IdentityId,
    pub(crate) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) nonce: [u8; 32],
    pub(crate) x25519_public: [u8; X25519_SIZE],
    pub(crate) kem_public_key: [u8; ML_KEM_768_EK_SIZE],
    pub(crate) signature: [u8; ML_DSA_65_SIG_SIZE],
    pub(crate) core: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct ParsedHandshakeAnswer {
    pub(crate) peer_id: IdentityId,
    pub(crate) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) offer_nonce: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) x25519_public: [u8; X25519_SIZE],
    pub(crate) kem_ciphertext: [u8; ML_KEM_768_CT_SIZE],
    pub(crate) signature: [u8; ML_DSA_65_SIG_SIZE],
    pub(crate) confirmation_tag: [u8; 32],
    pub(crate) core: Vec<u8>,
}

pub(crate) fn encode_handshake_offer(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
    x25519_public: [u8; X25519_SIZE],
    kem_public_key: &[u8; ML_KEM_768_EK_SIZE],
    signing_key: &MlDsaSigningKey,
) -> HydraResult<Vec<u8>> {
    let core = encode_offer_core(id, public_key, nonce, x25519_public, kem_public_key);
    let digest = offer_signature_digest(&core);
    let signature = RustCryptoBackend::mldsa65_sign(signing_key, &digest)?;
    Ok(append_signature(core, &signature))
}

pub(crate) fn encode_handshake_answer(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    offer_nonce: [u8; 32],
    nonce: [u8; 32],
    x25519_public: [u8; X25519_SIZE],
    kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
    offer: &ParsedHandshakeOffer,
    signing_key: &MlDsaSigningKey,
    x25519_secret: &SecretBytes<32>,
    kem_secret: &SecretBytes<32>,
) -> HydraResult<Vec<u8>> {
    let core = encode_answer_core(
        id,
        public_key,
        offer_nonce,
        nonce,
        x25519_public,
        kem_ciphertext,
    );
    let digest = answer_signature_digest(offer, &core);
    let signature = RustCryptoBackend::mldsa65_sign(signing_key, &digest)?;
    let confirmation_tag =
        answer_confirmation_tag(offer, &core, &signature, x25519_secret, kem_secret);
    Ok(append_answer_authentication(core, &signature, &confirmation_tag))
}

pub(crate) fn decode_handshake_offer(bytes: &[u8]) -> HydraResult<ParsedHandshakeOffer> {
    let values = parse_fields(bytes, OFFER_MAGIC)?;
    let public_key = values.public_key()?;
    let id = values.identity_id()?;
    verify_identity_id(id, &public_key)?;
    let parsed = ParsedHandshakeOffer {
        peer_id: id,
        public_key,
        nonce: values.nonce()?,
        x25519_public: values.x25519_public()?,
        kem_public_key: values.kem_public_key()?,
        signature: values.signature()?,
        core: Vec::new(),
    };
    let parsed = ParsedHandshakeOffer {
        core: encode_offer_core(
            parsed.peer_id,
            &parsed.public_key,
            parsed.nonce,
            parsed.x25519_public,
            &parsed.kem_public_key,
        ),
        ..parsed
    };
    verify_offer_signature(&parsed)?;
    Ok(parsed)
}

pub(crate) fn decode_handshake_answer(bytes: &[u8]) -> HydraResult<ParsedHandshakeAnswer> {
    let values = parse_fields(bytes, ANSWER_MAGIC)?;
    let public_key = values.public_key()?;
    let id = values.identity_id()?;
    verify_identity_id(id, &public_key)?;
    let parsed = ParsedHandshakeAnswer {
        peer_id: id,
        public_key,
        offer_nonce: values.offer_nonce()?,
        nonce: values.nonce()?,
        x25519_public: values.x25519_public()?,
        kem_ciphertext: values.kem_ciphertext()?,
        signature: values.signature()?,
        confirmation_tag: values.confirmation_tag()?,
        core: Vec::new(),
    };
    Ok(ParsedHandshakeAnswer {
        core: encode_answer_core(
            parsed.peer_id,
            &parsed.public_key,
            parsed.offer_nonce,
            parsed.nonce,
            parsed.x25519_public,
            &parsed.kem_ciphertext,
        ),
        ..parsed
    })
}

pub(crate) fn verify_answer_signature(
    answer: &ParsedHandshakeAnswer,
    offer: &ParsedHandshakeOffer,
) -> HydraResult<()> {
    if answer.offer_nonce != offer.nonce {
        return Err(HydraMsgError::InvalidEncoding("handshake nonce mismatch"));
    }
    let verifying_key = MlDsaVerificationKey::from_bytes(&answer.public_key)?;
    RustCryptoBackend::mldsa65_verify(
        &verifying_key,
        &answer_signature_digest(offer, &answer.core),
        &answer.signature,
    )?;
    Ok(())
}

pub(crate) fn verify_answer_confirmation(
    answer: &ParsedHandshakeAnswer,
    offer: &ParsedHandshakeOffer,
    x25519_secret: &SecretBytes<32>,
    kem_secret: &SecretBytes<32>,
) -> HydraResult<(SecretBytes<32>, [u8; TRANSCRIPT_HASH_SIZE])> {
    let (secret, transcript_hash) = derive_material_from_parts(
        offer,
        &answer.core,
        &answer.signature,
        x25519_secret,
        kem_secret,
    );
    RustCryptoBackend::verify_hmac_sha3_256(
        &secret,
        &confirmation_input(&transcript_hash),
        &answer.confirmation_tag,
    )?;
    Ok((secret, transcript_hash))
}

fn encode_offer_core(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
    x25519_public: [u8; X25519_SIZE],
    kem_public_key: &[u8; ML_KEM_768_EK_SIZE],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(OFFER_MAGIC);
    append_common_fields(&mut out, id, public_key, nonce, x25519_public);
    append_hex_field(&mut out, "kem_public_key", kem_public_key);
    out
}

fn encode_answer_core(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    offer_nonce: [u8; 32],
    nonce: [u8; 32],
    x25519_public: [u8; X25519_SIZE],
    kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ANSWER_MAGIC);
    append_hex_field(&mut out, "id", &id.0);
    append_hex_field(&mut out, "public_key", public_key);
    append_hex_field(&mut out, "offer_nonce", &offer_nonce);
    append_hex_field(&mut out, "nonce", &nonce);
    append_hex_field(&mut out, "x25519", &x25519_public);
    append_hex_field(&mut out, "kem_ciphertext", kem_ciphertext);
    out
}

fn append_common_fields(
    out: &mut Vec<u8>,
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
    x25519_public: [u8; X25519_SIZE],
) {
    append_hex_field(out, "id", &id.0);
    append_hex_field(out, "public_key", public_key);
    append_hex_field(out, "nonce", &nonce);
    append_hex_field(out, "x25519", &x25519_public);
}

fn append_hex_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.push(b':');
    out.extend_from_slice(hex_encode(value).as_bytes());
    out.push(b'\n');
}

fn append_signature(mut core: Vec<u8>, signature: &[u8; ML_DSA_65_SIG_SIZE]) -> Vec<u8> {
    append_hex_field(&mut core, "signature", signature);
    core
}

fn append_answer_authentication(
    mut core: Vec<u8>,
    signature: &[u8; ML_DSA_65_SIG_SIZE],
    confirmation_tag: &[u8; 32],
) -> Vec<u8> {
    append_hex_field(&mut core, "signature", signature);
    append_hex_field(&mut core, "confirmation_tag", confirmation_tag);
    core
}

fn verify_offer_signature(offer: &ParsedHandshakeOffer) -> HydraResult<()> {
    let verifying_key = MlDsaVerificationKey::from_bytes(&offer.public_key)?;
    RustCryptoBackend::mldsa65_verify(
        &verifying_key,
        &offer_signature_digest(&offer.core),
        &offer.signature,
    )?;
    Ok(())
}

fn offer_signature_digest(core: &[u8]) -> [u8; TRANSCRIPT_HASH_SIZE] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake/offer-signature");
    input.extend_from_slice(core);
    RustCryptoBackend::sha3_512(&input)
}

fn answer_signature_digest(
    offer: &ParsedHandshakeOffer,
    answer_core: &[u8],
) -> [u8; TRANSCRIPT_HASH_SIZE] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake/answer-signature");
    input.extend_from_slice(&offer.core);
    input.extend_from_slice(&offer.signature);
    input.extend_from_slice(answer_core);
    RustCryptoBackend::sha3_512(&input)
}

fn answer_confirmation_tag(
    offer: &ParsedHandshakeOffer,
    answer_core: &[u8],
    answer_signature: &[u8; ML_DSA_65_SIG_SIZE],
    x25519_secret: &SecretBytes<32>,
    kem_secret: &SecretBytes<32>,
) -> [u8; 32] {
    let (secret, transcript_hash) = derive_material_from_parts(
        offer,
        answer_core,
        answer_signature,
        x25519_secret,
        kem_secret,
    );
    RustCryptoBackend::hmac_sha3_256(&secret, &confirmation_input(&transcript_hash))
}

fn confirmation_input(transcript_hash: &[u8; TRANSCRIPT_HASH_SIZE]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake/answer-confirmation");
    input.extend_from_slice(transcript_hash);
    input
}

fn derive_material_from_parts(
    offer: &ParsedHandshakeOffer,
    answer_core: &[u8],
    answer_signature: &[u8; ML_DSA_65_SIG_SIZE],
    x25519_secret: &SecretBytes<32>,
    kem_secret: &SecretBytes<32>,
) -> (SecretBytes<32>, [u8; TRANSCRIPT_HASH_SIZE]) {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake/hybrid-transcript");
    transcript.extend_from_slice(&offer.core);
    transcript.extend_from_slice(&offer.signature);
    transcript.extend_from_slice(answer_core);
    transcript.extend_from_slice(answer_signature);
    let transcript_hash = RustCryptoBackend::sha3_512(&transcript);

    let mut input_key_material = Vec::new();
    input_key_material.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake/hybrid-secret");
    input_key_material.extend_from_slice(x25519_secret.expose_secret());
    input_key_material.extend_from_slice(kem_secret.expose_secret());
    let secret = RustCryptoBackend::hkdf_extract(&transcript_hash, &input_key_material);
    (secret, transcript_hash)
}

fn verify_identity_id(id: IdentityId, public_key: &[u8; ML_DSA_65_VK_SIZE]) -> HydraResult<()> {
    if id != IdentityId(RustCryptoBackend::sha3_256(public_key)) {
        return Err(HydraMsgError::InvalidEncoding(
            "handshake identity mismatch",
        ));
    }
    Ok(())
}
