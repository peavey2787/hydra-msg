use super::{exact_array_from_vec, hex_decode};
use crate::{HydraMsgError, HydraResult, IdentityId};
use hydra_core::{
    ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE, ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE,
    X25519_SIZE,
};

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
        self.id.ok_or(HydraMsgError::InvalidEncoding("handshake id"))
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
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return Err(HydraMsgError::InvalidEncoding("handshake field"));
        };
        set_field(&mut fields, name, value)?;
    }
    Ok(fields)
}

fn set_field(fields: &mut ParsedFields, name: &str, value: &str) -> HydraResult<()> {
    match name {
        "id" => set_once(&mut fields.id, IdentityId::from_hex(value)?)?,
        "public_key" => set_once(
            &mut fields.public_key,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "nonce" => set_once(
            &mut fields.nonce,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "offer_nonce" => set_once(
            &mut fields.offer_nonce,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "x25519" => set_once(
            &mut fields.x25519_public,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "kem_public_key" => set_once(
            &mut fields.kem_public_key,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "kem_ciphertext" => set_once(
            &mut fields.kem_ciphertext,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "signature" => set_once(
            &mut fields.signature,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        "confirmation_tag" => set_once(
            &mut fields.confirmation_tag,
            exact_array_from_vec(hex_decode(value)?)?,
        )?,
        _ => return Err(HydraMsgError::InvalidEncoding("handshake field")),
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> HydraResult<()> {
    if slot.is_some() {
        return Err(HydraMsgError::InvalidEncoding("duplicate handshake field"));
    }
    *slot = Some(value);
    Ok(())
}
