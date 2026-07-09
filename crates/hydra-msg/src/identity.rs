use crate::{codec::*, Hydra, HydraMsgError, HydraResult};
use hydra_core::{HASH_SIZE, ML_DSA_65_VK_SIZE};

/// HYDRA identity id/fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdentityId(pub(crate) [u8; HASH_SIZE]);

impl IdentityId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: impl AsRef<str>) -> HydraResult<Self> {
        Ok(Self(exact_array_from_vec(hex_decode(hex.as_ref())?)?))
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

/// Public identity metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraIdentitySummary {
    pub(crate) id: IdentityId,
    pub(crate) label: String,
    pub(crate) unlocked: bool,
}

impl HydraIdentitySummary {
    #[must_use]
    pub const fn id(&self) -> IdentityId {
        self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub const fn unlocked(&self) -> bool {
        self.unlocked
    }
}

#[derive(Clone)]
pub(crate) struct IdentityRecord {
    pub(crate) id: IdentityId,
    pub(crate) label: String,
    pub(crate) seed: Option<[u8; 32]>,
    pub(crate) public_key: [u8; ML_DSA_65_VK_SIZE],
    pub(crate) password_tag: [u8; 32],
    pub(crate) seed_nonce: [u8; 12],
    pub(crate) encrypted_seed: Vec<u8>,
    pub(crate) unlocked: bool,
}

impl Hydra {
    pub fn generate_id(&mut self, password: impl AsRef<str>) -> HydraResult<IdentityId> {
        let seed = random_array::<32>()?;
        let record = identity_record_from_seed(
            format!("identity-{}", self.identities.len() + 1),
            seed,
            password.as_ref(),
            true,
        )?;
        let id = record.id;
        if self.state_key.is_none() {
            self.state_key = Some(state_key(password.as_ref()));
        }
        self.identities.insert(id, record);
        self.persist()?;
        Ok(id)
    }

    pub fn import_id(
        &mut self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<IdentityId> {
        let seed = decode_identity_export(bytes.as_ref())?;
        let record = identity_record_from_seed(
            format!("imported-{}", self.identities.len() + 1),
            seed,
            password.as_ref(),
            false,
        )?;
        let id = record.id;
        if self.state_key.is_none() {
            self.state_key = Some(state_key(password.as_ref()));
        }
        self.identities.insert(id, record);
        self.persist()?;
        Ok(id)
    }

    pub fn export_id(&self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        let record = self
            .identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        verify_password(record, password.as_ref())?;
        Ok(encode_identity_export(
            &self.identity_seed(record, password.as_ref())?,
        ))
    }

    #[must_use]
    pub fn list_ids(&self) -> Vec<HydraIdentitySummary> {
        self.identities
            .values()
            .map(|record| HydraIdentitySummary {
                id: record.id,
                label: record.label.clone(),
                unlocked: record.unlocked,
            })
            .collect()
    }

    pub fn get_id(&self, id: IdentityId) -> HydraResult<HydraIdentitySummary> {
        let record = self
            .identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        Ok(HydraIdentitySummary {
            id: record.id,
            label: record.label.clone(),
            unlocked: record.unlocked,
        })
    }

    #[must_use]
    pub const fn active_id(&self) -> Option<IdentityId> {
        self.active_id
    }

    pub fn set_active_id(&mut self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<()> {
        self.unlock_id(id, password.as_ref())?;
        if self.state_key.is_none() {
            self.state_key = Some(state_key(password.as_ref()));
            self.persist()?;
        }
        self.active_id = Some(id);
        Ok(())
    }

    pub fn unlock_id(&mut self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<()> {
        let record = self
            .identities
            .get_mut(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        verify_password(record, password.as_ref())?;
        record.seed = Some(decrypt_seed(record, password.as_ref())?);
        record.unlocked = true;
        Ok(())
    }

    pub fn lock_id(&mut self, id: IdentityId) -> HydraResult<()> {
        let record = self
            .identities
            .get_mut(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        record.seed = None;
        record.unlocked = false;
        if self.active_id == Some(id) {
            self.active_id = None;
        }
        Ok(())
    }

    pub fn lock_active_id(&mut self) -> HydraResult<()> {
        let id = self.active_id.ok_or(HydraMsgError::IdentityNotFound)?;
        self.lock_id(id)
    }

    pub fn rename_id(&mut self, id: IdentityId, label: impl Into<String>) -> HydraResult<()> {
        let record = self
            .identities
            .get_mut(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        record.label = label.into();
        self.persist()?;
        Ok(())
    }

    pub fn delete_id(&mut self, id: IdentityId, password: impl AsRef<str>) -> HydraResult<()> {
        let record = self
            .identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)?;
        verify_password(record, password.as_ref())?;
        self.identities.remove(&id);
        if self.active_id == Some(id) {
            self.active_id = None;
        }
        self.persist()?;
        Ok(())
    }

    pub(crate) fn identity_seed(
        &self,
        record: &IdentityRecord,
        password: &str,
    ) -> HydraResult<[u8; 32]> {
        if let Some(seed) = record.seed {
            verify_password(record, password)?;
            return Ok(seed);
        }
        decrypt_seed(record, password)
    }

    pub(crate) fn active_record(&self) -> HydraResult<&IdentityRecord> {
        let id = self.active_id.ok_or(HydraMsgError::IdentityNotFound)?;
        self.identities
            .get(&id)
            .ok_or(HydraMsgError::IdentityNotFound)
    }

    pub(crate) fn active_unlocked_record(&self) -> HydraResult<&IdentityRecord> {
        let record = self.active_record()?;
        if record.unlocked && record.seed.is_some() {
            Ok(record)
        } else {
            Err(HydraMsgError::InvalidInput("active identity is locked"))
        }
    }
}
