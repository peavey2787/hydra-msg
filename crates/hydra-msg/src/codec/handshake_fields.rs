use super::{exact_array_from_vec, hex_decode};
use crate::{HydraMsgError, HydraResult, IdentityId};
use hydra_core::{
    HASH_SIZE, ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE, ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE,
    X25519_SIZE,
};

const MAX_HANDSHAKE_FIELDS: usize = 8;
const MAX_HANDSHAKE_FIELD_LINE_BYTES: usize = ML_DSA_65_SIG_SIZE * 2 + 32;

#[derive(Default)]
pub(super) struct ParsedFields {
    id: Option<IdentityId>,
    public_key: Option<[u8; ML_DSA_65_VK_SIZE]>,
    nonce: Option<[u8; 32]>,
    offer_nonce: Option<[u8; 32]>,
    x25519_public: Option<[u8; X25519_SIZE]>,
    kem_public_key: Option<[u8; ML_KEM_768_EK_SIZE]>,
    kem_ciphertext: Option<[u8; ML_KEM_768_CT_SIZE]>,
    signature: Option<[u8; ML_DSA_65_SIG_SIZE]>,
    confirmation_tag: Option<[u8; 32]>,
}

impl ParsedFields {
    pub(super) fn identity_id(&self) -> HydraResult<IdentityId> {
        self.id
            .ok_or(HydraMsgError::InvalidEncoding("handshake id"))
    }

    pub(super) fn public_key(&self) -> HydraResult<[u8; ML_DSA_65_VK_SIZE]> {
        self.public_key
            .ok_or(HydraMsgError::InvalidEncoding("handshake public key"))
    }

    pub(super) fn nonce(&self) -> HydraResult<[u8; 32]> {
        self.nonce
            .ok_or(HydraMsgError::InvalidEncoding("handshake nonce"))
    }

    pub(super) fn offer_nonce(&self) -> HydraResult<[u8; 32]> {
        self.offer_nonce
            .ok_or(HydraMsgError::InvalidEncoding("handshake offer nonce"))
    }

    pub(super) fn x25519_public(&self) -> HydraResult<[u8; X25519_SIZE]> {
        self.x25519_public
            .ok_or(HydraMsgError::InvalidEncoding("handshake x25519"))
    }

    pub(super) fn kem_public_key(&self) -> HydraResult<[u8; ML_KEM_768_EK_SIZE]> {
        self.kem_public_key
            .ok_or(HydraMsgError::InvalidEncoding("handshake kem public key"))
    }

    pub(super) fn kem_ciphertext(&self) -> HydraResult<[u8; ML_KEM_768_CT_SIZE]> {
        self.kem_ciphertext
            .ok_or(HydraMsgError::InvalidEncoding("handshake kem ciphertext"))
    }

    pub(super) fn signature(&self) -> HydraResult<[u8; ML_DSA_65_SIG_SIZE]> {
        self.signature
            .ok_or(HydraMsgError::InvalidEncoding("handshake signature"))
    }

    pub(super) fn confirmation_tag(&self) -> HydraResult<[u8; 32]> {
        self.confirmation_tag
            .ok_or(HydraMsgError::InvalidEncoding("handshake confirmation"))
    }
}

pub(super) fn parse_fields(bytes: &[u8], magic: &[u8]) -> HydraResult<ParsedFields> {
    if !bytes.starts_with(magic) {
        return Err(HydraMsgError::InvalidEncoding("handshake magic"));
    }
    let text = std::str::from_utf8(&bytes[magic.len()..])
        .map_err(|_| HydraMsgError::InvalidEncoding("handshake utf-8"))?;
    let mut fields = ParsedFields::default();
    let mut field_count = 0;
    for line in text.lines() {
        field_count += 1;
        if field_count > MAX_HANDSHAKE_FIELDS || line.len() > MAX_HANDSHAKE_FIELD_LINE_BYTES {
            return Err(HydraMsgError::InvalidEncoding(
                "handshake field count or size",
            ));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HydraMsgError::InvalidEncoding("handshake field"));
        };
        set_field(&mut fields, name, value)?;
    }
    Ok(fields)
}

fn set_field(fields: &mut ParsedFields, name: &str, value: &str) -> HydraResult<()> {
    match name {
        "id" => set_once(
            &mut fields.id,
            IdentityId::from_bytes(decode_fixed_hex::<HASH_SIZE>(value, "handshake id")?),
        )?,
        "public_key" => set_once(
            &mut fields.public_key,
            decode_fixed_hex::<ML_DSA_65_VK_SIZE>(value, "handshake public key")?,
        )?,
        "nonce" => set_once(
            &mut fields.nonce,
            decode_fixed_hex::<32>(value, "handshake nonce")?,
        )?,
        "offer_nonce" => set_once(
            &mut fields.offer_nonce,
            decode_fixed_hex::<32>(value, "handshake offer nonce")?,
        )?,
        "x25519" => set_once(
            &mut fields.x25519_public,
            decode_fixed_hex::<X25519_SIZE>(value, "handshake x25519")?,
        )?,
        "kem_public_key" => set_once(
            &mut fields.kem_public_key,
            decode_fixed_hex::<ML_KEM_768_EK_SIZE>(value, "handshake kem public key")?,
        )?,
        "kem_ciphertext" => set_once(
            &mut fields.kem_ciphertext,
            decode_fixed_hex::<ML_KEM_768_CT_SIZE>(value, "handshake kem ciphertext")?,
        )?,
        "signature" => set_once(
            &mut fields.signature,
            decode_fixed_hex::<ML_DSA_65_SIG_SIZE>(value, "handshake signature")?,
        )?,
        "confirmation_tag" => set_once(
            &mut fields.confirmation_tag,
            decode_fixed_hex::<32>(value, "handshake confirmation")?,
        )?,
        _ => return Err(HydraMsgError::InvalidEncoding("handshake field")),
    }
    Ok(())
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    description: &'static str,
) -> HydraResult<[u8; N]> {
    if value.len() != N * 2 {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    exact_array_from_vec(hex_decode(value)?)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> HydraResult<()> {
    if slot.is_some() {
        return Err(HydraMsgError::InvalidEncoding("duplicate handshake field"));
    }
    *slot = Some(value);
    Ok(())
}
