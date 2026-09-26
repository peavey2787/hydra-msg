use super::*;

pub(super) fn encode_offer_core(
    nonce: [u8; 32],
    expected_responder_fingerprint: [u8; 32],
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    x25519_public: [u8; X25519_SIZE],
    kem_public_key: &[u8; ML_KEM_768_EK_SIZE],
) -> Vec<u8> {
    let mut core = Vec::with_capacity(INIT_CORE_SIZE);
    core.push(PROTOCOL_VERSION);
    core.extend_from_slice(&SUITE_ID);
    core.extend_from_slice(&nonce);
    core.extend_from_slice(&expected_responder_fingerprint);
    core.extend_from_slice(public_key);
    core.extend_from_slice(&x25519_public);
    core.extend_from_slice(kem_public_key);
    debug_assert_eq!(core.len(), INIT_CORE_SIZE);
    core
}

pub(super) fn encode_answer_core(
    init_hash: [u8; TRANSCRIPT_HASH_SIZE],
    nonce: [u8; 32],
    initiator_fingerprint: [u8; 32],
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    x25519_public: [u8; X25519_SIZE],
    kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
) -> Vec<u8> {
    let mut core = Vec::with_capacity(RESP_CORE_SIZE);
    core.push(PROTOCOL_VERSION);
    core.extend_from_slice(&SUITE_ID);
    core.extend_from_slice(&init_hash);
    core.extend_from_slice(&nonce);
    core.extend_from_slice(&initiator_fingerprint);
    core.extend_from_slice(public_key);
    core.extend_from_slice(&x25519_public);
    core.extend_from_slice(kem_ciphertext);
    debug_assert_eq!(core.len(), RESP_CORE_SIZE);
    core
}

pub(super) fn encode_bootstrap(
    mode: OuterMode,
    route_tag: [u8; 16],
    control: &[u8],
    signature: &[u8; ML_DSA_65_SIG_SIZE],
    authenticator: &[u8; 32],
) -> HydraResult<Vec<u8>> {
    let header = encode_outer_header(&OuterHeader::new(
        mode,
        EnvelopeClass::Standard,
        route_tag,
        0,
    ))
    .map_err(|_| HydraMsgError::InvalidEncoding("bootstrap outer header"))?;
    let mut envelope = vec![0; EnvelopeClass::Standard.envelope_size()];
    envelope[..OUTER_HEADER_SIZE].copy_from_slice(&header);
    let body = &mut envelope[OUTER_HEADER_SIZE..];
    let control_len = u32::try_from(control.len())
        .map_err(|_| HydraMsgError::InvalidEncoding("bootstrap control length"))?;
    body[..BOOTSTRAP_CONTROL_LEN_SIZE].copy_from_slice(&control_len.to_be_bytes());
    let control_end = BOOTSTRAP_CONTROL_LEN_SIZE + control.len();
    let sig_end = control_end + signature.len();
    let auth_end = sig_end + authenticator.len();
    if auth_end > body.len() {
        return Err(HydraMsgError::InvalidEncoding("bootstrap body size"));
    }
    body[BOOTSTRAP_CONTROL_LEN_SIZE..control_end].copy_from_slice(control);
    body[control_end..sig_end].copy_from_slice(signature);
    body[sig_end..auth_end].copy_from_slice(authenticator);
    Ok(envelope)
}

pub(super) fn decode_bootstrap(
    bytes: &[u8],
    expected_mode: OuterMode,
    expected_control_size: usize,
) -> HydraResult<(Vec<u8>, [u8; ML_DSA_65_SIG_SIZE], [u8; 32])> {
    if bytes.len() != EnvelopeClass::Standard.envelope_size() {
        return Err(HydraMsgError::InvalidEncoding("bootstrap envelope size"));
    }
    let header = decode_outer_header(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("bootstrap outer header"))?;
    if header.mode != expected_mode
        || header.envelope_class != EnvelopeClass::Standard
        || header.counter != 0
    {
        return Err(HydraMsgError::InvalidEncoding("bootstrap header mismatch"));
    }
    let body = &bytes[OUTER_HEADER_SIZE..];
    let control_len = u32::from_be_bytes(
        body.get(..4)
            .ok_or(HydraMsgError::InvalidEncoding("bootstrap control length"))?
            .try_into()
            .map_err(|_| HydraMsgError::InvalidEncoding("bootstrap control length"))?,
    ) as usize;
    if control_len != expected_control_size {
        return Err(HydraMsgError::InvalidEncoding("bootstrap control size"));
    }
    let control_end = 4usize
        .checked_add(control_len)
        .ok_or(HydraMsgError::InvalidEncoding("bootstrap body offsets"))?;
    let sig_end = control_end
        .checked_add(ML_DSA_65_SIG_SIZE)
        .ok_or(HydraMsgError::InvalidEncoding("bootstrap body offsets"))?;
    let auth_end = sig_end
        .checked_add(32)
        .ok_or(HydraMsgError::InvalidEncoding("bootstrap body offsets"))?;
    if auth_end > body.len() || body[auth_end..].iter().any(|byte| *byte != 0) {
        return Err(HydraMsgError::InvalidEncoding("bootstrap padding"));
    }
    Ok((
        body[4..control_end].to_vec(),
        body[control_end..sig_end]
            .try_into()
            .map_err(|_| HydraMsgError::InvalidEncoding("bootstrap signature"))?,
        body[sig_end..auth_end]
            .try_into()
            .map_err(|_| HydraMsgError::InvalidEncoding("bootstrap authenticator"))?,
    ))
}

pub(super) fn offer_signature_digest(core: &[u8]) -> [u8; TRANSCRIPT_HASH_SIZE] {
    hash512(&[
        b"HYDRA-MSG/v1/init-signature",
        &SUITE_ID,
        &length_prefixed(core),
    ])
}

pub(super) fn init_hash(
    core: &[u8],
    signature: &[u8; ML_DSA_65_SIG_SIZE],
) -> [u8; TRANSCRIPT_HASH_SIZE] {
    let mut signed = Vec::with_capacity(core.len() + signature.len());
    signed.extend_from_slice(core);
    signed.extend_from_slice(signature);
    hash512(&[b"HYDRA-MSG/v1/transcript", &length_prefixed(&signed)])
}

pub(super) fn answer_signature_digest(
    init_hash: [u8; TRANSCRIPT_HASH_SIZE],
    core: &[u8],
) -> [u8; TRANSCRIPT_HASH_SIZE] {
    hash512(&[
        b"HYDRA-MSG/v1/resp-signature",
        &SUITE_ID,
        &init_hash,
        &length_prefixed(core),
    ])
}

pub(super) fn derive_material_from_parts(
    offer: &ParsedHandshakeOffer,
    answer_core: &[u8],
    answer_signature: &[u8; ML_DSA_65_SIG_SIZE],
    x25519_secret: &SecretBytes<32>,
    kem_secret: &SecretBytes<32>,
) -> HandshakeMaterial {
    let mut init_signed = Vec::with_capacity(offer.core.len() + offer.signature.len());
    init_signed.extend_from_slice(&offer.core);
    init_signed.extend_from_slice(&offer.signature);
    let mut resp_signed = Vec::with_capacity(answer_core.len() + answer_signature.len());
    resp_signed.extend_from_slice(answer_core);
    resp_signed.extend_from_slice(answer_signature);
    let transcript_hash = hash512(&[
        b"HYDRA-MSG/v1/transcript",
        &length_prefixed(&init_signed),
        &length_prefixed(&resp_signed),
    ]);
    let mut hybrid_ikm = Vec::with_capacity(72);
    let secret_len = 32_u32.to_be_bytes();
    hybrid_ikm.extend_from_slice(&secret_len);
    hybrid_ikm.extend_from_slice(x25519_secret.expose_secret());
    hybrid_ikm.extend_from_slice(&secret_len);
    hybrid_ikm.extend_from_slice(kem_secret.expose_secret());
    let hybrid_prk = RustCryptoBackend::hkdf_extract(&transcript_hash, &hybrid_ikm);
    let handshake_secret = derive_expand32(&hybrid_prk, b"HYDRA-MSG/v1/root-key", &transcript_hash);
    let sid = derive_expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/session-id",
        &transcript_hash,
    );
    let session_id = *sid.expose_secret();
    let finish_key = derive_expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/finish-key",
        &transcript_hash,
    );
    HandshakeMaterial {
        handshake_secret,
        transcript_hash,
        session_id,
        finish_key,
    }
}

pub(super) fn response_confirmation(material: &HandshakeMaterial) -> [u8; 32] {
    let confirm_key = derive_expand32(
        &material.handshake_secret,
        b"HYDRA-MSG/v1/confirm-key",
        &material.transcript_hash,
    );
    let input = confirmation_input(&material.transcript_hash, &material.session_id);
    RustCryptoBackend::hmac_sha3_256(&confirm_key, &input)
}

pub(super) fn confirmation_input(
    transcript_hash: &[u8; TRANSCRIPT_HASH_SIZE],
    session_id: &[u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(26 + transcript_hash.len() + session_id.len());
    input.extend_from_slice(b"HYDRA-MSG/v1/resp-confirm");
    input.extend_from_slice(transcript_hash);
    input.extend_from_slice(session_id);
    input
}

pub(super) fn derive_expand32(
    key: &SecretBytes<32>,
    label: &'static [u8],
    context: &[u8; TRANSCRIPT_HASH_SIZE],
) -> SecretBytes<32> {
    let label_len = u32::try_from(label.len()).expect("handshake KDF labels fit u32");
    let context_len = u32::try_from(context.len()).expect("transcript hash length fits u32");
    let mut info = Vec::with_capacity(label.len() + context.len() + 8);
    info.extend_from_slice(&label_len.to_be_bytes());
    info.extend_from_slice(label);
    info.extend_from_slice(&context_len.to_be_bytes());
    info.extend_from_slice(context);
    let output = RustCryptoBackend::hkdf_expand(key.expose_secret(), &info, 32)
        .expect("fixed-size handshake HKDF expansion is within backend limits");
    let bytes: [u8; 32] = output
        .as_slice()
        .try_into()
        .expect("handshake HKDF requests exactly 32 bytes");
    SecretBytes::from_array(bytes)
}

pub(super) fn length_prefixed(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    append_lp(&mut out, value).expect("protocol value lengths fit u32");
    out
}

pub(super) fn append_lp(out: &mut Vec<u8>, value: &[u8]) -> HydraResult<()> {
    let len = u32::try_from(value.len())
        .map_err(|_| HydraMsgError::InvalidEncoding("length-prefixed value"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

pub(super) fn hash512(parts: &[&[u8]]) -> [u8; TRANSCRIPT_HASH_SIZE] {
    let total = parts.iter().map(|part| part.len()).sum();
    let mut input = Vec::with_capacity(total);
    for part in parts {
        input.extend_from_slice(part);
    }
    RustCryptoBackend::sha3_512(&input)
}

pub(super) fn require_byte(
    bytes: &[u8],
    at: &mut usize,
    expected: u8,
    description: &'static str,
) -> HydraResult<()> {
    let byte = *bytes
        .get(*at)
        .ok_or(HydraMsgError::InvalidEncoding(description))?;
    *at += 1;
    if byte != expected {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

pub(super) fn require_slice(
    bytes: &[u8],
    at: &mut usize,
    expected: &[u8],
    description: &'static str,
) -> HydraResult<()> {
    let end = (*at)
        .checked_add(expected.len())
        .ok_or(HydraMsgError::InvalidEncoding(description))?;
    if bytes.get(*at..end) != Some(expected) {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    *at = end;
    Ok(())
}

pub(super) fn take_array<const N: usize>(
    bytes: &[u8],
    at: &mut usize,
    description: &'static str,
) -> HydraResult<[u8; N]> {
    let end = (*at)
        .checked_add(N)
        .ok_or(HydraMsgError::InvalidEncoding(description))?;
    let value = bytes
        .get(*at..end)
        .ok_or(HydraMsgError::InvalidEncoding(description))?
        .try_into()
        .map_err(|_| HydraMsgError::InvalidEncoding(description))?;
    *at = end;
    Ok(value)
}
