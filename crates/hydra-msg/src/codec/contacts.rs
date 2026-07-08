use super::{escape_line, exact_array_from_vec, hex_decode, hex_encode, unescape_line};
use crate::{ContactId, HydraContact, HydraMsgError, HydraResult, CONTACT_CARD_MAGIC};
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
    .join("	")
}

pub(crate) fn decode_contact_line(line: &str) -> HydraResult<HydraContact> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 6 || parts[0] != "contact" {
        return Err(HydraMsgError::InvalidEncoding("contact state record"));
    }
    let id = ContactId(exact_array_from_vec(hex_decode(parts[1])?)?);
    let label = String::from_utf8(hex_decode(parts[2])?)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact label"))?;
    let public_key = exact_array_from_vec(hex_decode(parts[3])?)?;
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
        verified: parts[4] == "1",
        blocked: parts[5] == "1",
    })
}

pub(crate) fn encode_contact_card(label: &str, public_key: &[u8; ML_DSA_65_VK_SIZE]) -> Vec<u8> {
    let id = RustCryptoBackend::sha3_256(public_key);
    format!(
        "{CONTACT_CARD_MAGIC}\nlabel:{}\nid:{}\npublic_key:{}\nsafety:{}\n",
        escape_line(label),
        hex_encode(&id),
        hex_encode(public_key),
        safety_code_for_contact(ContactId(id))
    )
    .into_bytes()
}

pub(crate) fn decode_contact_card(bytes: &[u8]) -> HydraResult<HydraContact> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact card utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(CONTACT_CARD_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("contact card magic"));
    }
    let mut label = None;
    let mut id = None;
    let mut public_key = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("label:") {
            label = Some(unescape_line(value));
        } else if let Some(value) = line.strip_prefix("id:") {
            id = Some(ContactId(exact_array_from_vec(hex_decode(value)?)?));
        } else if let Some(value) = line.strip_prefix("public_key:") {
            public_key = Some(exact_array_from_vec(hex_decode(value)?)?);
        }
    }
    let public_key = public_key.ok_or(HydraMsgError::InvalidEncoding("contact public key"))?;
    let expected_id = ContactId(RustCryptoBackend::sha3_256(&public_key));
    let id = id.unwrap_or(expected_id);
    if id != expected_id {
        return Err(HydraMsgError::InvalidEncoding(
            "contact fingerprint mismatch",
        ));
    }
    Ok(HydraContact {
        id,
        label: label.unwrap_or_else(|| format!("contact-{}", id.hex())),
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
