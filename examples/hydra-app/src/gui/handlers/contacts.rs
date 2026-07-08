use hydra_app_core::IdentityVault;

use crate::{
    config::AppConfig,
    contacts::{outcome_record, ContactBookAddOutcome, ContactRecord, ContactTrustWarning},
    services,
};

use super::{
    json::{contact_record_json, public_contact_card_json},
    support::optional_bool,
};
use crate::gui::{
    encoding::json_escape,
    forms::{parse_form, required_form_value},
    state::GuiAppState,
};

pub(crate) fn api_contacts_my_card(app_state: &GuiAppState) -> Result<String, String> {
    let config = AppConfig::load_or_default()?;
    let vault = IdentityVault::open(&config.data_dir).map_err(|error| error.to_string())?;
    let mut session = app_state.lock_identity_session()?;
    let material = session
        .active_public_material(&vault)
        .map_err(|error| error.to_string())?;
    let card =
        services::active_contact_card_from_public_key(&material.label, &material.public_key_hex)?;
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"message\":\"public contact card created\",",
            "\"card\":{}",
            "}}"
        ),
        public_contact_card_json(&card),
    ))
}

pub(crate) fn api_contacts_add(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let alias = required_form_value(&form, "alias")?;
    let public_key_hex = form
        .get("public_key_hex")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let outcome = services::add_contact(
        alias,
        if public_key_hex.is_empty() {
            None
        } else {
            Some(public_key_hex)
        },
    )?;
    match outcome_record(outcome) {
        Ok(contact) => Ok(format!(
            concat!(
                "{{",
                "\"ok\":true,",
                "\"trusted\":true,",
                "\"alias\":\"{}\",",
                "\"fingerprint\":\"{}\",",
                "\"mailbox\":\"{}\",",
                "\"safety\":\"{}\",",
                "\"qr\":\"{}\"",
                "}}"
            ),
            json_escape(&contact.alias),
            json_escape(&contact.fingerprint_hex),
            json_escape(&contact.mailbox_hint),
            json_escape(&contact.safety_number),
            json_escape(&contact.qr_payload),
        )),
        Err(warning) => Ok(format!(
            concat!(
                "{{",
                "\"ok\":true,",
                "\"trusted\":false,",
                "\"key_change_warning\":true,",
                "\"alias\":\"{}\",",
                "\"old_fingerprint\":\"{}\",",
                "\"new_fingerprint\":\"{}\",",
                "\"old_safety\":\"{}\",",
                "\"new_safety\":\"{}\",",
                "\"message\":\"{}\"",
                "}}"
            ),
            json_escape(&warning.alias),
            json_escape(&warning.old_fingerprint_hex),
            json_escape(&warning.new_fingerprint_hex),
            json_escape(&warning.old_safety_number),
            json_escape(&warning.new_safety_number),
            json_escape(warning.message),
        )),
    }
}

pub(crate) fn api_contacts_review(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let alias = required_form_value(&form, "alias")?;
    let public_key_hex = form
        .get("public_key_hex")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let qr_payload = form
        .get("qr_payload")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if public_key_hex.is_empty() && qr_payload.is_empty() {
        return Err("contact review requires a public key or QR verification payload".to_owned());
    }
    let outcome = services::review_contact(
        alias,
        if public_key_hex.is_empty() {
            None
        } else {
            Some(public_key_hex)
        },
        if qr_payload.is_empty() {
            None
        } else {
            Some(qr_payload)
        },
    )?;
    Ok(contact_review_response_json(
        outcome,
        "contact safety review created",
    ))
}

pub(crate) fn api_contacts_trust(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let alias = required_form_value(&form, "alias")?;
    let public_key_hex = form
        .get("public_key_hex")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let qr_payload = form
        .get("qr_payload")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if public_key_hex.is_empty() && qr_payload.is_empty() {
        return Err("trust decision requires a public key or QR verification payload".to_owned());
    }
    let confirm_safety = optional_bool(form.get("confirm_safety").map(String::as_str))?;
    if !confirm_safety {
        return Err("safety confirmation is required before trusting a contact".to_owned());
    }
    let accept_key_change = optional_bool(form.get("accept_key_change").map(String::as_str))?;
    let outcome = services::trust_contact(
        alias,
        if public_key_hex.is_empty() {
            None
        } else {
            Some(public_key_hex)
        },
        if qr_payload.is_empty() {
            None
        } else {
            Some(qr_payload)
        },
        accept_key_change,
    )?;
    match outcome_record(outcome) {
        Ok(contact) => Ok(contact_trusted_response_json(
            &contact,
            "contact trust decision saved",
        )),
        Err(warning) => Ok(contact_warning_response_json(
            warning.as_ref(),
            "contact key changed; explicit key-change acceptance is required",
        )),
    }
}

pub(crate) fn api_contacts_verify_qr(body: &[u8]) -> Result<String, String> {
    let form = parse_form(body)?;
    let alias = required_form_value(&form, "alias")?;
    let qr_payload = required_form_value(&form, "qr_payload")?;
    let verified = services::verify_contact_qr(alias, qr_payload)?;
    Ok(format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"alias\":\"{}\",",
            "\"verified\":{},",
            "\"trust_state\":\"{}\",",
            "\"message\":\"{}\"",
            "}}"
        ),
        json_escape(alias),
        verified,
        if verified { "trusted" } else { "unverified" },
        if verified {
            "QR verification matched the trusted contact"
        } else {
            "QR verification did not match a trusted contact"
        },
    ))
}

fn contact_review_response_json(outcome: ContactBookAddOutcome, message: &str) -> String {
    match outcome {
        ContactBookAddOutcome::Added(contact) => format!(
            concat!(
                "{{",
                "\"ok\":true,",
                "\"trusted\":false,",
                "\"decision_required\":true,",
                "\"trust_state\":\"unverified\",",
                "\"message\":\"{}\",",
                "\"contact\":{}",
                "}}"
            ),
            json_escape(message),
            contact_record_json(&contact),
        ),
        ContactBookAddOutcome::AlreadyTrusted(contact) => format!(
            concat!(
                "{{",
                "\"ok\":true,",
                "\"trusted\":true,",
                "\"decision_required\":false,",
                "\"trust_state\":\"trusted\",",
                "\"message\":\"contact is already trusted\",",
                "\"contact\":{}",
                "}}"
            ),
            contact_record_json(&contact),
        ),
        ContactBookAddOutcome::KeyChangeWarning(warning) => contact_warning_response_json(
            &warning,
            "contact key changed; verify the new safety number or QR before trusting",
        ),
    }
}

pub(crate) fn contact_trusted_response_json(contact: &ContactRecord, message: &str) -> String {
    format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"trusted\":true,",
            "\"decision_required\":false,",
            "\"trust_state\":\"trusted\",",
            "\"message\":\"{}\",",
            "\"contact\":{}",
            "}}"
        ),
        json_escape(message),
        contact_record_json(contact),
    )
}

pub(crate) fn contact_warning_response_json(
    warning: &ContactTrustWarning,
    message: &str,
) -> String {
    format!(
        concat!(
            "{{",
            "\"ok\":true,",
            "\"trusted\":false,",
            "\"decision_required\":true,",
            "\"key_change_warning\":true,",
            "\"trust_state\":\"changed-key-warning\",",
            "\"alias\":\"{}\",",
            "\"old_fingerprint\":\"{}\",",
            "\"new_fingerprint\":\"{}\",",
            "\"old_safety\":\"{}\",",
            "\"new_safety\":\"{}\",",
            "\"message\":\"{}\",",
            "\"warning\":\"{}\"",
            "}}"
        ),
        json_escape(&warning.alias),
        json_escape(&warning.old_fingerprint_hex),
        json_escape(&warning.new_fingerprint_hex),
        json_escape(&warning.old_safety_number),
        json_escape(&warning.new_safety_number),
        json_escape(message),
        json_escape(warning.message),
    )
}
