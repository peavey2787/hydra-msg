use super::{exact_array_from_vec, hex_decode, hex_encode};
use crate::{
    limits::{
        reject_encoded_size, validate_label_encoding, MAX_CONTACT_CARD_BYTES, MAX_LABEL_BYTES,
    },
    ContactId, HydraContact, HydraMsgError, HydraResult, CONTACT_CARD_MAGIC,
};
use hydra_core::ML_DSA_65_VK_SIZE;
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

pub(crate) fn encode_contact_line(contact: &HydraContact) -> String {
    [
        "contact".to_string(),
        contact.id.hex(),
        hex_encode(contact.label.as_bytes()),
        hex_encode(&contact.public_key),
        if contact.verified { "1" } else { "0" }.to_string(),
        if contact.blocked { "1" } else { "0" }.to_string(),
    ]
    .join("\t")
}

pub(crate) fn decode_contact_line(line: &str) -> HydraResult<HydraContact> {
    let mut parts = line.split('\t');
    if parts.next() != Some("contact") {
        return Err(HydraMsgError::InvalidEncoding("contact state record"));
    }
    let id_hex = required_part(parts.next(), "contact id")?;
    if id_hex.len() != hydra_core::HASH_SIZE * 2 {
        return Err(HydraMsgError::InvalidEncoding("contact id size"));
    }
    let id = ContactId(exact_array_from_vec(hex_decode(id_hex)?)?);
    let label_hex = required_part(parts.next(), "contact label")?;
    reject_encoded_size(label_hex.len(), MAX_LABEL_BYTES * 2, "contact label size")?;
    let label = String::from_utf8(hex_decode(label_hex)?)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact label"))?;
    validate_label_encoding(&label, "contact label size")?;
    let public_key_hex = required_part(parts.next(), "contact public key")?;
    reject_encoded_size(
        public_key_hex.len(),
        ML_DSA_65_VK_SIZE * 2,
        "contact public key size",
    )?;
    let public_key = exact_array_from_vec(hex_decode(public_key_hex)?)?;
    let verified = parse_bool(required_part(parts.next(), "contact verified")?)?;
    let blocked = parse_bool(required_part(parts.next(), "contact blocked")?)?;
    if parts.next().is_some() {
        return Err(HydraMsgError::InvalidEncoding("contact state record"));
    }
    let expected_id = ContactId(RustCryptoBackend::sha3_256(&public_key));
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "contact fingerprint mismatch",
        ));
    }
    Ok(HydraContact {
        id,
        label,
        public_key,
        verified,
        blocked,
    })
}

pub(crate) fn encode_contact_card(
    label: Option<&str>,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
) -> Vec<u8> {
    let mut out = format!(
        "{CONTACT_CARD_MAGIC}\npublic_key:{}\n",
        hex_encode(public_key)
    );
    if let Some(label) = label.filter(|label| !label.trim().is_empty()) {
        out.push_str("label:");
        out.push_str(&hex_encode(label.trim().as_bytes()));
        out.push('\n');
    }
    out.into_bytes()
}

pub(crate) fn decode_contact_card(bytes: &[u8]) -> HydraResult<HydraContact> {
    reject_encoded_size(bytes.len(), MAX_CONTACT_CARD_BYTES, "contact card size")?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact card utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(CONTACT_CARD_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("contact card magic"));
    }
    let mut label = None;
    let mut public_key = None;
    let mut field_count = 0_usize;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        field_count += 1;
        if field_count > 2 {
            return Err(HydraMsgError::InvalidEncoding("contact card field count"));
        }
        if let Some(value) = line.strip_prefix("label:") {
            if label.is_some() {
                return Err(HydraMsgError::InvalidEncoding(
                    "duplicate contact card label",
                ));
            }
            reject_encoded_size(value.len(), MAX_LABEL_BYTES * 2, "contact label size")?;
            let decoded = String::from_utf8(hex_decode(value)?)
                .map_err(|_| HydraMsgError::InvalidEncoding("contact card label"))?;
            validate_label_encoding(&decoded, "contact label size")?;
            label = Some(decoded);
        } else if let Some(value) = line.strip_prefix("public_key:") {
            if public_key.is_some() {
                return Err(HydraMsgError::InvalidEncoding(
                    "duplicate contact public key",
                ));
            }
            reject_encoded_size(
                value.len(),
                ML_DSA_65_VK_SIZE * 2,
                "contact public key size",
            )?;
            public_key = Some(exact_array_from_vec(hex_decode(value)?)?);
        } else {
            return Err(HydraMsgError::InvalidEncoding("contact card field"));
        }
    }
    let public_key = public_key.ok_or(HydraMsgError::InvalidEncoding("contact public key"))?;
    let id = ContactId(RustCryptoBackend::sha3_256(&public_key));
    Ok(HydraContact {
        id,
        label: label.unwrap_or_default(),
        public_key,
        verified: false,
        blocked: false,
    })
}

pub(crate) fn safety_code_for_contact(contact_id: ContactId) -> String {
    let hex = contact_id.hex();
    hex.as_bytes()
        .chunks(4)
        .take(6)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

fn required_part<'a>(value: Option<&'a str>, description: &'static str) -> HydraResult<&'a str> {
    value.ok_or(HydraMsgError::InvalidEncoding(description))
}

fn parse_bool(value: &str) -> HydraResult<bool> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(HydraMsgError::InvalidEncoding("contact boolean")),
    }
}
