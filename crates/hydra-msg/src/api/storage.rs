#[cfg(not(target_arch = "wasm32"))]
use crate::persistence::{native_store::NativeStateStore, rollback};
use crate::{
    codec::PasswordKdfRecord,
    persistence::{backup, encrypted_snapshot},
    Hydra, HydraResult,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

impl Hydra {
    pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>) -> HydraResult<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();

        #[cfg(not(target_arch = "wasm32"))]
        {
            let store = NativeStateStore::new(data_dir.clone());
            store.ensure_dir()?;
            let native_profile_lock = store.acquire_profile_lock()?;
            let state_kdf = if store.state_exists() {
                encrypted_snapshot::read_state_kdf(&store.read_encrypted_snapshot()?)?
            } else {
                encrypted_snapshot::new_state_kdf()?
            };
            let state_key =
                encrypted_snapshot::derive_state_key(state_password.as_ref(), &state_kdf)?;
            let mut hydra = Self::empty(data_dir, state_key, state_kdf)?;
            hydra._native_profile_lock = Some(native_profile_lock);
            hydra.load_state(&store)?;
            Ok(hydra)
        }

        #[cfg(target_arch = "wasm32")]
        {
            Self::open_with_encrypted_state_snapshot_inner(data_dir, state_password, None)
        }
    }

    pub fn open_default(state_password: impl AsRef<str>) -> HydraResult<Self> {
        Self::open("hydra-msg-data", state_password)
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    fn open_with_encrypted_state_snapshot_inner(
        data_dir: impl AsRef<Path>,
        state_password: impl AsRef<str>,
        encrypted_state_snapshot: Option<&[u8]>,
    ) -> HydraResult<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        let state_kdf = if let Some(bytes) = encrypted_state_snapshot {
            encrypted_snapshot::read_state_kdf(bytes)?
        } else {
            encrypted_snapshot::new_state_kdf()?
        };
        let state_key = encrypted_snapshot::derive_state_key(state_password.as_ref(), &state_kdf)?;
        let mut hydra = Self::empty(data_dir, state_key, state_kdf)?;
        if let Some(bytes) = encrypted_state_snapshot {
            let snapshot = encrypted_snapshot::open_state_snapshot(bytes, &hydra.state_key)?;
            hydra.apply_state_snapshot(&snapshot)?;
        }
        Ok(hydra)
    }

    #[cfg(test)]
    pub(crate) fn open_with_encrypted_state_snapshot(
        data_dir: impl AsRef<Path>,
        state_password: impl AsRef<str>,
        encrypted_state_snapshot: Option<&[u8]>,
    ) -> HydraResult<Self> {
        Self::open_with_encrypted_state_snapshot_inner(
            data_dir,
            state_password,
            encrypted_state_snapshot,
        )
    }

    fn flush_encrypted_state_snapshot_inner(&mut self) -> HydraResult<Vec<u8>> {
        let previous_generation = self.state_generation;
        self.state_generation = self.state_generation.saturating_add(1);
        let persist_result = (|| -> HydraResult<Vec<u8>> {
            let snapshot = self.encode_state_snapshot()?;
            encrypted_snapshot::seal_state_snapshot(&snapshot, &self.state_key, &self.state_kdf)
        })();
        if persist_result.is_err() {
            self.state_generation = previous_generation;
        }
        persist_result
    }

    #[cfg(test)]
    pub(crate) fn flush_encrypted_state_snapshot(&mut self) -> HydraResult<Vec<u8>> {
        self.flush_encrypted_state_snapshot_inner()
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn open_browser_persistent(
        name: impl AsRef<str>,
        state_password: impl AsRef<str>,
    ) -> HydraResult<(Self, u64)> {
        let name = name.as_ref();
        let persistent_snapshot = crate::browser_persistence::load_encrypted_snapshot(name).await?;
        let hydra = Self::open_with_encrypted_state_snapshot_inner(
            name,
            state_password,
            persistent_snapshot.bytes.as_deref(),
        )?;
        Ok((hydra, persistent_snapshot.revision))
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn delete_browser_persistent(name: impl AsRef<str>) -> HydraResult<()> {
        crate::browser_persistence::delete_encrypted_snapshot(name.as_ref()).await
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn flush_browser_persistent(
        &mut self,
        name: impl AsRef<str>,
        expected_revision: u64,
    ) -> HydraResult<u64> {
        let previous_generation = self.state_generation;
        let encrypted_snapshot = self.flush_encrypted_state_snapshot_inner()?;
        match crate::browser_persistence::save_encrypted_snapshot(
            name.as_ref(),
            &encrypted_snapshot,
            expected_revision,
        )
        .await
        {
            Ok(new_revision) => Ok(new_revision),
            Err(error) => {
                self.state_generation = previous_generation;
                Err(error)
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn browser_lifecycle_status() -> HydraResult<String> {
        crate::browser_persistence::lifecycle_status_json().await
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn request_persistent_storage() -> HydraResult<bool> {
        crate::browser_persistence::request_persistence().await
    }

    pub fn change_state_password(
        &mut self,
        old_password: impl AsRef<str>,
        new_password: impl AsRef<str>,
    ) -> HydraResult<()> {
        let old_password = old_password.as_ref();
        let new_password = new_password.as_ref();
        let old_key = encrypted_snapshot::derive_state_key(old_password, &self.state_kdf)?;
        if old_key.expose_secret() != self.state_key.expose_secret() {
            return Err(crate::HydraMsgError::InvalidPassword);
        }
        let previous_kdf = self.state_kdf.clone();
        let previous_key = encrypted_snapshot::derive_state_key(old_password, &previous_kdf)?;
        let new_kdf = encrypted_snapshot::new_state_kdf()?;
        let new_key = encrypted_snapshot::derive_state_key(new_password, &new_kdf)?;
        self.state_kdf = new_kdf;
        self.state_key = new_key;
        if let Err(error) = self.persist() {
            self.state_kdf = previous_kdf;
            self.state_key = previous_key;
            return Err(error);
        }
        Ok(())
    }

    pub fn export_backup(&self, password: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        let snapshot = self.encode_state_snapshot()?;
        backup::export_verified_backup_snapshot(&snapshot, password.as_ref())
    }

    pub fn import_backup(
        &mut self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<()> {
        let snapshot = backup::open_verified_backup_snapshot(bytes.as_ref(), password.as_ref())?;
        self.restore_verified_backup_snapshot(&snapshot)
    }

    pub fn verify_backup(
        &self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<()> {
        backup::open_verified_backup_snapshot(bytes.as_ref(), password.as_ref()).map(|_| ())
    }

    fn restore_verified_backup_snapshot(&mut self, snapshot: &[u8]) -> HydraResult<()> {
        let previous_snapshot = self.encode_state_snapshot()?;
        let previous_generation = self.state_generation;
        self.apply_state_snapshot(snapshot)?;
        self.state_generation = self.state_generation.max(previous_generation);
        let persist_result = self.persist();
        if let Err(persist_error) = persist_result {
            self.apply_state_snapshot(&previous_snapshot)?;
            return Err(persist_error);
        }
        Ok(())
    }

    fn empty(
        data_dir: PathBuf,
        state_key: hydra_crypto::SecretBytes<32>,
        state_kdf: PasswordKdfRecord,
    ) -> HydraResult<Self> {
        Ok(Self {
            data_dir,
            #[cfg(not(target_arch = "wasm32"))]
            _native_profile_lock: None,
            identities: HashMap::new(),
            active_id: None,
            contacts: HashMap::new(),
            pending_offers: HashMap::new(),
            sessions: HashMap::new(),
            receive_routes: HashMap::new(),
            session_route_tags: HashMap::new(),
            messages: Vec::new(),
            message_usage: HashMap::new(),
            stored_message_bytes: 0,
            next_message_id: 1,
            lobbies: HashMap::new(),
            anonymous_auth_secret: hydra_crypto::SecretBytes::from_array(
                crate::codec::random_array::<32>()?,
            ),
            anonymous_auth_spent: Vec::new(),
            anonymous_auth_spent_index: HashSet::new(),
            state_key,
            state_kdf,
            state_generation: 0,
            packet_size: crate::envelope_limits::DEFAULT_PACKET_SIZE,
            pending_fragments: HashMap::new(),
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn load_state(&mut self, store: &NativeStateStore) -> HydraResult<()> {
        if !store.state_exists() {
            return Ok(());
        }
        let bytes = store.read_encrypted_snapshot()?;
        let snapshot = encrypted_snapshot::open_state_snapshot(&bytes, &self.state_key)?;
        self.apply_state_snapshot(&snapshot)?;
        rollback::reject_state_rollback(store, self.state_generation)?;
        rollback::write_rollback_guard(store, self.state_generation)?;
        Ok(())
    }

    pub(crate) fn persist(&mut self) -> HydraResult<()> {
        #[cfg(target_arch = "wasm32")]
        {
            return Ok(());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let previous_generation = self.state_generation;
            let encrypted = self.flush_encrypted_state_snapshot_inner()?;
            let store = NativeStateStore::new(self.data_dir.clone());
            let persist_result = (|| -> HydraResult<()> {
                store.write_encrypted_snapshot(&encrypted)?;
                rollback::write_rollback_guard(&store, self.state_generation)?;
                Ok(())
            })();
            if persist_result.is_err() {
                self.state_generation = previous_generation;
            }
            persist_result
        }
    }
}
