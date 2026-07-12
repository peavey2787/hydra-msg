use crate::{
    codec::*,
    limits::{
        reject_collection_growth, reject_decoded_collection_growth, reject_encoded_size,
        reject_input_size, validate_label_input, MAX_CONTACTS, MAX_CONTACT_IMPORT_BYTES,
        MAX_IDENTITIES, MAX_IMPORTED_CONTACTS,
    },
    Hydra, HydraMsgError, HydraResult, IdentityId, CONTACTS_MAGIC,
};
use hydra_core::{HASH_SIZE, ML_DSA_65_VK_SIZE};
use std::collections::HashMap;

/// HYDRA contact id. This is the contact identity fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContactId(pub(crate) [u8; HASH_SIZE]);

impl ContactId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: impl AsRef<str>) -> HydraResult<Self> {
        let hex = hex.as_ref();
        if hex.len() != HASH_SIZE * 2 {
            return Err(HydraMsgError::InvalidEncoding("contact id size"));
        }
        Ok(Self(exact_array_from_vec(hex_decode(hex)?)?))
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    #[must_use]
    pub fn hex(self) -> String {
        hex_encode(&self.0)
    }
}

/// Public contact metadata stored locally after a contact card is imported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraContact {
    pub(crate) id: ContactId,
    pub(crate) label: String,
    pub(crate) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) verified: bool,
    pub(crate) blocked: bool,
}

impl HydraContact {
    #[must_use]
    pub const fn id(&self) -> ContactId {
        self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8; ML_DSA_65_VK_SIZE] {
        &self.public_key
    }

    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    #[must_use]
    pub const fn blocked(&self) -> bool {
        self.blocked
    }

    #[must_use]
    pub fn safety_code(&self) -> String {
        safety_code_for_contact(self.id)
    }
}

/// Fresh one-time contact-card output for unlinkable chat setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraOneTimeContactCard {
    pub(crate) identity_id: IdentityId,
    pub(crate) card: Vec<u8>,
}

impl HydraOneTimeContactCard {
    #[must_use]
    pub const fn identity_id(&self) -> IdentityId {
        self.identity_id
    }

    #[must_use]
    pub fn card(&self) -> &[u8] {
        &self.card
    }

    #[must_use]
    pub fn into_card(self) -> Vec<u8> {
        self.card
    }

    #[must_use]
    pub fn into_parts(self) -> (IdentityId, Vec<u8>) {
        (self.identity_id, self.card)
    }
}

impl AsRef<[u8]> for HydraOneTimeContactCard {
    fn as_ref(&self) -> &[u8] {
        self.card()
    }
}

impl Hydra {
    pub fn create_contact_card(&self) -> HydraResult<Vec<u8>> {
        let record = self.active_record()?;
        Ok(encode_contact_card(None, &record.public_key))
    }

    pub fn create_labeled_contact_card(&self, label: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        let record = self.active_record()?;
        let label = label.as_ref().trim();
        if label.is_empty() {
            return self.create_contact_card();
        }
        validate_label_input(label, "contact label size")?;
        Ok(encode_contact_card(Some(label), &record.public_key))
    }

    pub fn create_one_time_contact_card(
        &mut self,
        password: impl AsRef<str>,
    ) -> HydraResult<HydraOneTimeContactCard> {
        reject_collection_growth(
            self.identities.len(),
            1,
            MAX_IDENTITIES,
            "identity limit reached",
        )?;
        let seed = random_array::<32>()?;
        let record = identity_record_from_seed(String::new(), seed, password.as_ref(), true)?;
        let identity_id = record.id;
        let card = encode_contact_card(None, &record.public_key);
        self.identities.insert(identity_id, record);
        self.active_id = Some(identity_id);
        self.persist()?;
        Ok(HydraOneTimeContactCard { identity_id, card })
    }

    pub fn create_contact_invite(&self) -> HydraResult<Vec<u8>> {
        self.create_contact_card()
    }

    pub fn preview_contact_card(
        &self,
        contact_card: impl AsRef<[u8]>,
    ) -> HydraResult<HydraContact> {
        decode_contact_card(contact_card.as_ref())
    }

    pub fn add_contact(&mut self, contact_card: impl AsRef<[u8]>) -> HydraResult<HydraContact> {
        let contact = decode_contact_card(contact_card.as_ref())?;
        if !self.contacts.contains_key(&contact.id) {
            reject_collection_growth(
                self.contacts.len(),
                1,
                MAX_CONTACTS,
                "contact limit reached",
            )?;
        }
        self.contacts.insert(contact.id, contact.clone());
        self.persist()?;
        Ok(contact)
    }

    pub fn import_contacts(&mut self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        let bytes = bytes.as_ref();
        reject_encoded_size(
            bytes.len(),
            MAX_CONTACT_IMPORT_BYTES,
            "contacts import size",
        )?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| HydraMsgError::InvalidEncoding("contacts export is not utf-8"))?;
        let mut parsed = HashMap::<ContactId, HydraContact>::new();
        let mut record_count = 0_usize;

        if text.starts_with(std::str::from_utf8(CONTACTS_MAGIC).unwrap_or_default()) {
            for line in text.lines().skip(1) {
                if line.trim().is_empty() {
                    continue;
                }
                reject_decoded_collection_growth(
                    record_count,
                    1,
                    MAX_IMPORTED_CONTACTS,
                    "contacts import count",
                )?;
                record_count += 1;
                let contact = decode_contact_line(line)?;
                if parsed.insert(contact.id, contact).is_some() {
                    return Err(HydraMsgError::InvalidEncoding(
                        "duplicate contact import record",
                    ));
                }
            }
        } else {
            for block in text.split("\n---\n") {
                if block.trim().is_empty() {
                    continue;
                }
                reject_decoded_collection_growth(
                    record_count,
                    1,
                    MAX_IMPORTED_CONTACTS,
                    "contacts import count",
                )?;
                record_count += 1;
                let contact = decode_contact_card(block.as_bytes())?;
                if parsed.insert(contact.id, contact).is_some() {
                    return Err(HydraMsgError::InvalidEncoding(
                        "duplicate contact import record",
                    ));
                }
            }
        }

        let new_contacts = parsed
            .keys()
            .filter(|contact_id| !self.contacts.contains_key(contact_id))
            .count();
        reject_collection_growth(
            self.contacts.len(),
            new_contacts,
            MAX_CONTACTS,
            "contact limit reached",
        )?;
        let affected_contacts = parsed.keys().copied().collect::<Vec<_>>();
        self.contacts.extend(parsed);
        for contact_id in affected_contacts {
            if self
                .contacts
                .get(&contact_id)
                .is_some_and(|contact| contact.blocked)
            {
                self.remove_session_routes(contact_id);
            } else {
                self.refresh_session_routes(contact_id)?;
            }
        }
        self.persist()?;
        Ok(())
    }

    pub fn export_contacts(&self) -> HydraResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(CONTACTS_MAGIC);
        for contact in self.contacts.values() {
            out.extend_from_slice(encode_contact_line(contact).as_bytes());
            out.push(b'\n');
            reject_input_size(out.len(), MAX_CONTACT_IMPORT_BYTES, "contacts export size")?;
        }
        Ok(out)
    }

    #[must_use]
    pub fn list_contacts(&self) -> Vec<HydraContact> {
        self.contacts.values().cloned().collect()
    }

    pub fn get_contact(&self, contact_id: ContactId) -> HydraResult<HydraContact> {
        self.contacts
            .get(&contact_id)
            .cloned()
            .ok_or(HydraMsgError::ContactNotFound)
    }

    pub fn verify_contact(
        &mut self,
        contact_id: ContactId,
        safety_code: impl AsRef<str>,
    ) -> HydraResult<()> {
        let expected = safety_code_for_contact(contact_id);
        if expected != safety_code.as_ref() {
            return Err(HydraMsgError::InvalidInput("contact safety code mismatch"));
        }
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.verified = true;
        self.persist()?;
        Ok(())
    }

    pub fn unverify_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.verified = false;
        self.persist()?;
        Ok(())
    }

    pub fn rename_contact(
        &mut self,
        contact_id: ContactId,
        label: impl Into<String>,
    ) -> HydraResult<()> {
        let label = label.into();
        validate_label_input(&label, "contact label size")?;
        let contact = self
            .contacts
            .get_mut(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        contact.label = label;
        self.persist()?;
        Ok(())
    }

    pub fn remove_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        let previous_snapshot = self.encode_state_snapshot()?;
        self.contacts
            .remove(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)?;
        self.remove_session_routes(contact_id);
        self.sessions.remove(&contact_id);
        self.session_security_policies.remove(&contact_id);
        self.pending_fragments
            .retain(|key, _| key.from() != contact_id);
        if let Err(error) = self.persist() {
            let _ = self.apply_state_snapshot(&previous_snapshot);
            return Err(error);
        }
        Ok(())
    }

    pub fn block_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        {
            let contact = self
                .contacts
                .get_mut(&contact_id)
                .ok_or(HydraMsgError::ContactNotFound)?;
            contact.blocked = true;
        }
        self.remove_session_routes(contact_id);
        self.pending_fragments
            .retain(|key, _| key.from() != contact_id);
        self.persist()?;
        Ok(())
    }

    pub fn unblock_contact(&mut self, contact_id: ContactId) -> HydraResult<()> {
        {
            let contact = self
                .contacts
                .get_mut(&contact_id)
                .ok_or(HydraMsgError::ContactNotFound)?;
            contact.blocked = false;
        }
        self.refresh_session_routes(contact_id)?;
        self.persist()?;
        Ok(())
    }

    pub(crate) fn require_contact(&self, contact_id: ContactId) -> HydraResult<&HydraContact> {
        self.contacts
            .get(&contact_id)
            .ok_or(HydraMsgError::ContactNotFound)
    }
}
