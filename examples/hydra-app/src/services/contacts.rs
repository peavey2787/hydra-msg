use hydra_app_core::PublicContactCard;

use crate::contacts::{outcome_record, ContactBook, ContactBookAddOutcome, ContactRecord};

use super::{context::AppContext, identity::active_identity_public_material};

pub fn contact_records() -> Result<Vec<ContactRecord>, String> {
    let context = AppContext::load()?;
    Ok(context.contact_book()?.contacts())
}

pub fn active_contact_card(identity_password: &[u8]) -> Result<PublicContactCard, String> {
    let material = active_identity_public_material(identity_password)?;
    PublicContactCard::create(&material.label, &material.public_key_hex)
        .map_err(|error| error.to_string())
}

pub fn active_contact_card_from_public_key(
    label: &str,
    public_key_hex: &str,
) -> Result<PublicContactCard, String> {
    PublicContactCard::create(label, public_key_hex).map_err(|error| error.to_string())
}

pub fn add_contact(
    alias: &str,
    public_key_hex: Option<&str>,
) -> Result<ContactBookAddOutcome, String> {
    let context = AppContext::load()?;
    let mut contacts = context.contact_book()?;
    let outcome = match public_key_hex
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(public_key_hex) => contacts.add_public_key_hex(alias, public_key_hex)?,
        None => contacts.add_generated(alias)?,
    };
    contacts.save(context.storage_secret())?;
    Ok(outcome)
}

pub fn review_contact(
    alias: &str,
    public_key_hex: Option<&str>,
    qr_payload: Option<&str>,
) -> Result<ContactBookAddOutcome, String> {
    let context = AppContext::load()?;
    let mut contacts = context.contact_book()?;
    contact_outcome_from_review(&mut contacts, alias, public_key_hex, qr_payload)
}

pub fn trust_contact(
    alias: &str,
    public_key_hex: Option<&str>,
    qr_payload: Option<&str>,
    accept_key_change: bool,
) -> Result<ContactBookAddOutcome, String> {
    let context = AppContext::load()?;
    let mut contacts = context.contact_book()?;
    let outcome =
        match contact_outcome_from_review(&mut contacts, alias, public_key_hex, qr_payload)? {
            ContactBookAddOutcome::KeyChangeWarning(_) if accept_key_change => {
                let public_key_hex = normalize_optional(public_key_hex);
                let qr_payload = normalize_optional(qr_payload);
                match (public_key_hex, qr_payload) {
                    (Some(public_key_hex), None) => {
                        contacts.accept_key_change_public_key_hex(alias, public_key_hex)?
                    }
                    (None, Some(qr_payload)) => {
                        contacts.accept_key_change_qr_payload(alias, qr_payload)?
                    }
                    _ => {
                        return Err(
                            "trust decision requires exactly one public key or QR payload"
                                .to_owned(),
                        )
                    }
                }
            }
            other => other,
        };
    if outcome_record(outcome.clone()).is_ok() {
        contacts.save(context.storage_secret())?;
    }
    Ok(outcome)
}

pub fn verify_contact_qr(alias: &str, qr_payload: &str) -> Result<bool, String> {
    let context = AppContext::load()?;
    context.contact_book()?.verify_qr_payload(alias, qr_payload)
}

fn contact_outcome_from_review(
    contacts: &mut ContactBook,
    alias: &str,
    public_key_hex: Option<&str>,
    qr_payload: Option<&str>,
) -> Result<ContactBookAddOutcome, String> {
    match (
        normalize_optional(public_key_hex),
        normalize_optional(qr_payload),
    ) {
        (Some(public_key_hex), None) => contacts.add_public_key_hex(alias, public_key_hex),
        (None, Some(qr_payload)) => contacts.add_qr_payload(alias, qr_payload),
        _ => Err("contact review requires exactly one public key or QR payload".to_owned()),
    }
}

fn normalize_optional(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}
