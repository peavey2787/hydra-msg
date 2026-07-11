use hydra_core::types::EnvelopeClass;
use hydra_envelope::{decode_outer_header, decode_protected_record};
use hydra_msg::{Hydra, HydraAnonymousAuthPolicy};

use crate::{corpus::FuzzInput, util};

pub fn run(inputs: &[FuzzInput]) -> util::FuzzResult<usize> {
    let mut cases = 0;
    for (index, input) in inputs.iter().enumerate() {
        util::no_panic("envelope-codecs", &input.name, input.bytes.len(), || {
            exercise_envelope_codecs(&input.bytes);
        })?;
        util::no_panic(
            "hydra-public-parsers",
            &input.name,
            input.bytes.len(),
            || {
                exercise_hydra_public_parsers(index, &input.bytes);
            },
        )?;
        cases += 2;
    }
    Ok(cases)
}

fn exercise_envelope_codecs(bytes: &[u8]) {
    let _ = decode_outer_header(bytes);
    for class in [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ] {
        let _ = decode_protected_record(class, bytes);
    }
}

fn exercise_hydra_public_parsers(index: usize, bytes: &[u8]) {
    let base = util::temp_case_dir("parser", index);
    let _ = std::fs::remove_dir_all(&base);

    let mut hydra = match Hydra::open(&base, "state-pw") {
        Ok(hydra) => hydra,
        Err(_) => return,
    };

    let snapshot_dir = base.join("snapshot-open");
    let _ = std::fs::create_dir_all(&snapshot_dir);
    let _ = std::fs::write(snapshot_dir.join("state.hydra"), bytes);
    let _ = Hydra::open(&snapshot_dir, "state-pw");
    let _ = hydra.verify_backup(bytes, "backup-pw");
    let _ = hydra.import_backup(bytes, "backup-pw");
    let _ = hydra.import_id(bytes, "id-pw");
    let _ = hydra.add_contact(bytes);
    let _ = hydra.import_contacts(bytes);
    let _ = hydra.reply_handshake(bytes);
    let _ = hydra.finish_handshake(bytes);
    let _ = hydra.join_lobby(bytes);
    let _ = hydra.receive(bytes);
    let _ = hydra.receive_lobby(bytes);
    let _ = hydra.anonymous_auth_nullifier(bytes);
    let _ = hydra.accept_anonymous_auth_token(bytes, "scope", "action", 0);
    let _ = hydra.revoke_anonymous_auth_token(bytes, "scope", "action");

    let policy = HydraAnonymousAuthPolicy::new("scope", "action").with_expiry(1);
    if let Ok(token) = hydra.issue_anonymous_auth_token(policy) {
        let mut token_bytes = token.into_bytes();
        token_bytes.extend_from_slice(&bytes[..bytes.len().min(8)]);
        let _ = hydra.accept_anonymous_auth_token(&token_bytes, "scope", "action", 0);
        let _ = hydra.revoke_anonymous_auth_token(&token_bytes, "scope", "action");
    }

    let _ = std::fs::remove_dir_all(&base);
}
