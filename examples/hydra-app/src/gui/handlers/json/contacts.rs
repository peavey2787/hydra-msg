use hydra_app_core::PublicContactCard;

use crate::contacts::ContactRecord;
use crate::gui::encoding::json_escape;

pub(crate) fn contact_record_json(contact: &ContactRecord) -> String {
    format!(
        concat!(
            "{{",
            "\"alias\":\"{}\",",
            "\"fingerprint\":\"{}\",",
            "\"public_key_hex\":\"{}\",",
            "\"mailbox\":\"{}\",",
            "\"mailbox_binding\":\"{}\",",
            "\"safety\":\"{}\",",
            "\"qr\":\"{}\",",
            "\"key_version\":{},",
            "\"trust_state\":\"trusted\",",
            "\"trusted\":true,",
            "\"verified\":true,",
            "\"revoked\":false",
            "}}"
        ),
        json_escape(&contact.alias),
        json_escape(&contact.fingerprint_hex),
        json_escape(&contact.public_key_hex),
        json_escape(&contact.mailbox_hint),
        json_escape(&contact.mailbox_binding_hex),
        json_escape(&contact.safety_number),
        json_escape(&contact.qr_payload),
        contact.key_version,
    )
}

pub(crate) fn public_contact_card_json(card: &PublicContactCard) -> String {
    format!(
        concat!(
            "{{",
            "\"label\":\"{}\",",
            "\"fingerprint\":\"{}\",",
            "\"public_key_hex\":\"{}\",",
            "\"mailbox\":\"{}\",",
            "\"mailbox_binding\":\"{}\",",
            "\"safety\":\"{}\",",
            "\"qr_payload\":\"{}\",",
            "\"join_code\":\"{}\"",
            "}}"
        ),
        json_escape(&card.label),
        json_escape(&card.fingerprint_hex),
        json_escape(&card.public_key_hex),
        json_escape(&card.mailbox_hint),
        json_escape(&card.mailbox_binding_hex),
        json_escape(&card.safety_number),
        json_escape(&card.qr_payload),
        json_escape(&card.join_code),
    )
}
