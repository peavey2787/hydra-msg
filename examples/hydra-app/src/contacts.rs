use std::{fmt, fs, path::Path};

use hydra_app_core::{
    ContactAddOutcome, ContactKeyChangeWarning, ContactTrustStore, TrustedContact,
};

const CONTACTS_FILE: &str = "contacts.db";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRecord {
    pub alias: String,
    pub fingerprint_hex: String,
    pub public_key_hex: String,
    pub mailbox_hint: String,
    pub mailbox_binding_hex: String,
    pub safety_number: String,
    pub qr_payload: String,
    pub added_at_ms: u64,
    pub updated_at_ms: u64,
    pub key_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactTrustWarning {
    pub alias: String,
    pub old_fingerprint_hex: String,
    pub new_fingerprint_hex: String,
    pub old_safety_number: String,
    pub new_safety_number: String,
    pub message: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactBookAddOutcome {
    Added(ContactRecord),
    AlreadyTrusted(ContactRecord),
    KeyChangeWarning(ContactTrustWarning),
}

#[derive(Clone, Debug)]
pub struct ContactBook {
    store: ContactTrustStore,
}

impl ContactBook {
    pub fn load(data_dir: &Path, storage_secret: &[u8]) -> Result<Self, String> {
        fs::create_dir_all(data_dir).map_err(|error| {
            format!("cannot create contacts dir {}: {error}", data_dir.display())
        })?;
        let path = data_dir.join(CONTACTS_FILE);
        let store = ContactTrustStore::create_or_load(&path, storage_secret)
            .map_err(|error| error.to_string())?;
        Ok(Self { store })
    }

    pub fn save(&self, storage_secret: &[u8]) -> Result<(), String> {
        self.store
            .save(storage_secret)
            .map_err(|error| error.to_string())
    }

    pub fn add_generated(&mut self, alias: &str) -> Result<ContactBookAddOutcome, String> {
        self.store
            .add_generated(alias)
            .map(map_outcome)
            .map_err(|error| error.to_string())
    }

    pub fn add_public_key_hex(
        &mut self,
        alias: &str,
        public_key_hex: &str,
    ) -> Result<ContactBookAddOutcome, String> {
        self.store
            .add_public_key_hex(alias, public_key_hex)
            .map(map_outcome)
            .map_err(|error| error.to_string())
    }

    pub fn accept_key_change_public_key_hex(
        &mut self,
        alias: &str,
        public_key_hex: &str,
    ) -> Result<ContactBookAddOutcome, String> {
        self.store
            .accept_key_change_public_key_hex(alias, public_key_hex)
            .map(map_outcome)
            .map_err(|error| error.to_string())
    }

    pub fn add_qr_payload(
        &mut self,
        alias: &str,
        payload: &str,
    ) -> Result<ContactBookAddOutcome, String> {
        self.store
            .add_qr_payload(alias, payload)
            .map(map_outcome)
            .map_err(|error| error.to_string())
    }

    pub fn accept_key_change_qr_payload(
        &mut self,
        alias: &str,
        payload: &str,
    ) -> Result<ContactBookAddOutcome, String> {
        self.store
            .accept_key_change_qr_payload(alias, payload)
            .map(map_outcome)
            .map_err(|error| error.to_string())
    }

    pub fn verify_qr_payload(&self, alias: &str, payload: &str) -> Result<bool, String> {
        self.store
            .verify_qr_payload(alias, payload)
            .map_err(|error| error.to_string())
    }

    pub fn contacts(&self) -> Vec<ContactRecord> {
        self.store
            .contacts()
            .iter()
            .map(record_from_trusted)
            .collect()
    }
}

impl fmt::Display for ContactRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}  fingerprint={}  mailbox={}  safety={}  key_version={}",
            self.alias,
            self.fingerprint_hex,
            self.mailbox_hint,
            self.safety_number,
            self.key_version,
        )
    }
}

impl fmt::Display for ContactTrustWarning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            concat!(
                "possible contact key change for '{}': old fingerprint={} new fingerprint={} ",
                "old safety={} new safety={}. {}"
            ),
            self.alias,
            self.old_fingerprint_hex,
            self.new_fingerprint_hex,
            self.old_safety_number,
            self.new_safety_number,
            self.message,
        )
    }
}

pub fn outcome_record(
    outcome: ContactBookAddOutcome,
) -> Result<ContactRecord, Box<ContactTrustWarning>> {
    match outcome {
        ContactBookAddOutcome::Added(record) | ContactBookAddOutcome::AlreadyTrusted(record) => {
            Ok(record)
        }
        ContactBookAddOutcome::KeyChangeWarning(warning) => Err(Box::new(warning)),
    }
}

fn map_outcome(outcome: ContactAddOutcome) -> ContactBookAddOutcome {
    match outcome {
        ContactAddOutcome::Added(contact) => {
            ContactBookAddOutcome::Added(record_from_trusted(&contact))
        }
        ContactAddOutcome::AlreadyTrusted(contact) => {
            ContactBookAddOutcome::AlreadyTrusted(record_from_trusted(&contact))
        }
        ContactAddOutcome::KeyChangeWarning(warning) => {
            ContactBookAddOutcome::KeyChangeWarning(warning_from_core(&warning))
        }
    }
}

fn record_from_trusted(contact: &TrustedContact) -> ContactRecord {
    ContactRecord {
        alias: contact.alias.clone(),
        fingerprint_hex: contact.fingerprint_hex.clone(),
        public_key_hex: contact.public_key_hex.clone(),
        mailbox_hint: contact.mailbox_hint.clone(),
        mailbox_binding_hex: contact.mailbox_binding_hex.clone(),
        safety_number: contact.safety_number.clone(),
        qr_payload: contact.qr_payload.clone(),
        added_at_ms: contact.added_at_ms,
        updated_at_ms: contact.updated_at_ms,
        key_version: contact.key_version,
    }
}

fn warning_from_core(warning: &ContactKeyChangeWarning) -> ContactTrustWarning {
    ContactTrustWarning {
        alias: warning.alias.clone(),
        old_fingerprint_hex: warning.old_fingerprint_hex.clone(),
        new_fingerprint_hex: warning.new_fingerprint_hex.clone(),
        old_safety_number: warning.old_safety_number.clone(),
        new_safety_number: warning.new_safety_number.clone(),
        message: warning.message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_book_adds_generated_peer_encrypted() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("hydra-contact-test-{unique}"));
        let secret = [7_u8; 32];
        let mut book = ContactBook::load(&path, &secret).unwrap();
        let record = outcome_record(book.add_generated("bob").unwrap()).unwrap();
        assert_eq!(record.alias, "bob");
        assert_eq!(book.contacts().len(), 1);
        assert!(matches!(
            book.add_generated("bob").unwrap(),
            ContactBookAddOutcome::KeyChangeWarning(_)
        ));
        book.save(&secret).unwrap();
        let bytes = fs::read(path.join(CONTACTS_FILE)).unwrap();
        assert!(!bytes.windows(b"bob".len()).any(|window| window == b"bob"));
        assert!(!path.join("contacts.txt").exists());
    }
}
