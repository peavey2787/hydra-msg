use super::{exact_array_from_vec, hex_decode, hex_encode};
use crate::{HydraMsgError, HydraResult, IdentityId, ANSWER_MAGIC, OFFER_MAGIC};
use hydra_core::{ML_DSA_65_VK_SIZE, TRANSCRIPT_HASH_SIZE};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

#[derive(Clone, Copy)]
pub(super) struct ParsedHandshake {
    pub(super) peer_id: IdentityId,
    pub(super) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(super) nonce: [u8; 32],
}

pub(super) fn encode_handshake_offer(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
) -> Vec<u8> {
    encode_handshake(OFFER_MAGIC, id, public_key, nonce)
}

pub(super) fn encode_handshake_answer(
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
) -> Vec<u8> {
    encode_handshake(ANSWER_MAGIC, id, public_key, nonce)
}

pub(super) fn encode_handshake(
    magic: &[u8],
    id: IdentityId,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(magic);
    out.extend_from_slice(b"id:");
    out.extend_from_slice(id.hex().as_bytes());
    out.extend_from_slice(b"\npublic_key:");
    out.extend_from_slice(hex_encode(public_key).as_bytes());
    out.extend_from_slice(b"\nnonce:");
    out.extend_from_slice(hex_encode(&nonce).as_bytes());
    out.push(b'\n');
    out
}

pub(super) fn decode_handshake_offer(bytes: &[u8]) -> HydraResult<ParsedHandshake> {
    decode_handshake(bytes, OFFER_MAGIC)
}

pub(super) fn decode_handshake_answer(bytes: &[u8]) -> HydraResult<ParsedHandshake> {
    decode_handshake(bytes, ANSWER_MAGIC)
}

pub(super) fn decode_handshake(bytes: &[u8], magic: &[u8]) -> HydraResult<ParsedHandshake> {
    if !bytes.starts_with(magic) {
        return Err(HydraMsgError::InvalidEncoding("handshake magic"));
    }
    let text = std::str::from_utf8(&bytes[magic.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("handshake utf-8"))?;
    let mut id = None;
    let mut public_key = None;
    let mut nonce = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("id:") {
            id = Some(IdentityId(exact_array_from_vec(hex_decode(value)?)?));
        } else if let Some(value) = line.strip_prefix("public_key:") {
            public_key = Some(exact_array_from_vec(hex_decode(value)?)?);
        } else if let Some(value) = line.strip_prefix("nonce:") {
            nonce = Some(exact_array_from_vec(hex_decode(value)?)?);
        }
    }
    let public_key = public_key.ok_or(HydraMsgError::InvalidEncoding("handshake public key"))?;
    let expected_id = IdentityId(RustCryptoBackend::sha3_256(&public_key));
    let id = id.ok_or(HydraMsgError::InvalidEncoding("handshake id"))?;
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "handshake identity mismatch",
        ));
    }
    Ok(ParsedHandshake {
        peer_id: id,
        public_key,
        nonce: nonce.ok_or(HydraMsgError::InvalidEncoding("handshake nonce"))?,
    })
}

pub(super) fn derive_facade_handshake_material(
    nonce: [u8; 32],
    left: IdentityId,
    right: IdentityId,
) -> (SecretBytes<32>, [u8; TRANSCRIPT_HASH_SIZE]) {
    let (a, b) = if left <= right {
        (left.0, right.0)
    } else {
        (right.0, left.0)
    };
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"HYDRA-MSG/v1/facade-handshake");
    transcript.extend_from_slice(&nonce);
    transcript.extend_from_slice(&a);
    transcript.extend_from_slice(&b);
    let transcript_hash = RustCryptoBackend::sha3_512(&transcript);
    let secret =
        RustCryptoBackend::hkdf_extract(b"HYDRA-MSG/v1/facade-handshake-secret", &transcript_hash);
    (secret, transcript_hash)
}
