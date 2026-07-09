use super::{exact_array_from_vec, hex_decode, hex_encode};
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
    .join("\t")
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

pub(crate) fn encode_contact_card(
    label: Option<&str>,
    public_key: &[u8; ML_DSA_65_VK_SIZE],
) -> Vec<u8> {
    let mut out = format!("{CONTACT_CARD_MAGIC}\npublic_key:{}\n", hex_encode(public_key));
    if let Some(label) = label.filter(|label| !label.trim().is_empty()) {
        out.push_str("label:");
        out.push_str(&hex_encode(label.trim().as_bytes()));
        out.push('\n');
    }
    out.into_bytes()
}

pub(crate) fn decode_contact_card(bytes: &[u8]) -> HydraResult<HydraContact> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HydraMsgError::InvalidEncoding("contact card utf-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(CONTACT_CARD_MAGIC) {
        return Err(HydraMsgError::InvalidEncoding("contact card magic"));
    }
    let mut label = None;
    let mut public_key = None;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("label:") {
            label = Some(
                String::from_utf8(hex_decode(value)?)
                    .map_err(|_| HydraMsgError::InvalidEncoding("contact card label"))?,
            );
        } else if let Some(value) = line.strip_prefix("public_key:") {
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
