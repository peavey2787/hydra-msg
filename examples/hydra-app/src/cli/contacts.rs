use crate::{
    contacts::{outcome_record, ContactBookAddOutcome, ContactRecord, ContactTrustWarning},
    services,
};

pub(super) fn run_contacts(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("list") => {
            print_contacts(&services::contact_records()?);
            Ok(())
        }
        Some("my-card") => {
            let password = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts my-card <identity-password>".to_owned()
            })?;
            let card = services::active_contact_card(password.as_bytes())?;
            println!("[My public contact card]");
            println!("label: {}", card.label);
            println!("fingerprint: {}", card.fingerprint_hex);
            println!("safety number: {}", card.safety_number);
            println!("mailbox: {}", card.mailbox_hint);
            println!("join code: {}", card.join_code);
            println!("QR payload: {}", card.qr_payload);
            Ok(())
        }
        Some("add") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts add <alias> [public-key-hex]".to_owned()
            })?;
            let outcome = services::add_contact(alias, args.get(2).map(String::as_str))?;
            print_contact_outcome(outcome, "trusted contact")
        }
        Some("review") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts review <alias> (--qr <payload> | --key <public-key-hex>)".to_owned()
            })?;
            let (public_key_hex, qr_payload) = parse_contact_key_or_qr(&args[2..])?;
            let outcome = services::review_contact(alias, public_key_hex, qr_payload)?;
            print_contact_outcome(outcome, "contact safety review")
        }
        Some("trust") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts trust <alias> (--qr <payload> | --key <public-key-hex>) [--accept-key-change]".to_owned()
            })?;
            let accept_key_change = args.iter().any(|arg| arg == "--accept-key-change");
            let (public_key_hex, qr_payload) = parse_contact_key_or_qr(&args[2..])?;
            let outcome =
                services::trust_contact(alias, public_key_hex, qr_payload, accept_key_change)?;
            print_contact_outcome(outcome, "contact trust decision")
        }
        Some("trust-update") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts trust-update <alias> <public-key-hex>".to_owned()
            })?;
            let public_key_hex = args.get(2).ok_or_else(|| {
                "usage: hydra-app contacts trust-update <alias> <public-key-hex>".to_owned()
            })?;
            let outcome = services::trust_contact(alias, Some(public_key_hex), None, true)?;
            print_contact_outcome(outcome, "trusted updated contact")
        }
        Some("add-qr") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts add-qr <alias> <qr-payload>".to_owned()
            })?;
            let payload = args.get(2).ok_or_else(|| {
                "usage: hydra-app contacts add-qr <alias> <qr-payload>".to_owned()
            })?;
            let outcome = services::trust_contact(alias, None, Some(payload), false)?;
            print_contact_outcome(outcome, "trusted QR contact")
        }
        Some("verify-qr") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app contacts verify-qr <alias> <qr-payload>".to_owned()
            })?;
            let payload = args.get(2).ok_or_else(|| {
                "usage: hydra-app contacts verify-qr <alias> <qr-payload>".to_owned()
            })?;
            println!(
                "QR verification: {}",
                services::verify_contact_qr(alias, payload)?
            );
            Ok(())
        }
        Some(other) => Err(format!("unknown contacts command '{other}'")),
    }
}

fn print_contacts(records: &[ContactRecord]) {
    println!("[Encrypted contacts]");
    if records.is_empty() {
        println!("no contacts yet");
        println!("add one with: hydra-app contacts add bob");
        return;
    }
    for contact in records {
        println!("{contact}");
        println!("  mailbox binding: {}", contact.mailbox_binding_hex);
        println!("  QR payload: {}", contact.qr_payload);
    }
}

fn print_contact_outcome(outcome: ContactBookAddOutcome, label: &str) -> Result<(), String> {
    match outcome_record(outcome) {
        Ok(record) => {
            println!("{label}: {record}");
            println!("safety number: {}", record.safety_number);
            println!("QR payload: {}", record.qr_payload);
            Ok(())
        }
        Err(warning) => {
            print_contact_warning(warning.as_ref());
            Err("refusing contact key change until explicit safety confirmation".to_owned())
        }
    }
}

fn print_contact_warning(warning: &ContactTrustWarning) {
    println!("{warning}");
}

fn parse_contact_key_or_qr(args: &[String]) -> Result<(Option<&str>, Option<&str>), String> {
    let mut public_key_hex = None;
    let mut qr_payload = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                index += 1;
                public_key_hex = Some(
                    args.get(index)
                        .ok_or_else(|| "--key requires a public key value".to_owned())?
                        .as_str(),
                );
            }
            "--qr" => {
                index += 1;
                qr_payload = Some(
                    args.get(index)
                        .ok_or_else(|| "--qr requires a payload value".to_owned())?
                        .as_str(),
                );
            }
            "--accept-key-change" => {}
            other => return Err(format!("unknown contact trust option '{other}'")),
        }
        index += 1;
    }
    match (public_key_hex, qr_payload) {
        (Some(_), None) | (None, Some(_)) => Ok((public_key_hex, qr_payload)),
        _ => Err("provide exactly one of --key or --qr".to_owned()),
    }
}
