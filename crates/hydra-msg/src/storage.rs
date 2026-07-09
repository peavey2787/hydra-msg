#[cfg(not(target_arch = "wasm32"))]
use crate::{STATE_FILE_NAME, STATE_ROLLBACK_FILE_NAME};
use crate::{codec::*, Hydra, HydraMsgError, HydraResult, STATE_SNAPSHOT_MAGIC};
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

/// Local storage summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraStorageStatus {
    pub data_dir: PathBuf,
    pub identity_count: usize,
    pub contact_count: usize,
    pub session_count: usize,
    pub message_count: usize,
    pub lobby_count: usize,
    pub encrypted_state: bool,
    pub state_generation: u64,
}

impl Hydra {
    pub fn open(data_dir: impl AsRef<Path>, state_password: impl AsRef<str>) -> HydraResult<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        #[cfg(not(target_arch = "wasm32"))]
        fs::create_dir_all(&data_dir)?;
        #[cfg(not(target_arch = "wasm32"))]
        let state_kdf = {
            let path = data_dir.join(STATE_FILE_NAME);
            if path.exists() {
                parse_state_v2_kdf(&fs::read(&path)?)?
            } else {
                new_storage_kdf()?
            }
        };
        #[cfg(target_arch = "wasm32")]
        let state_kdf = new_storage_kdf()?;
        let state_key = state_key(state_password.as_ref(), &state_kdf)?;
        let mut hydra = Self::empty(data_dir, state_key, state_kdf);
        hydra.load_state()?;
        Ok(hydra)
    }

    pub fn open_default(state_password: impl AsRef<str>) -> HydraResult<Self> {
        Self::open("hydra-msg-data", state_password)
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn export_backup(&self, password: impl AsRef<str>) -> HydraResult<Vec<u8>> {
        let snapshot = self.encode_state_snapshot()?;
        let kdf = new_storage_kdf()?;
        encode_backup(&snapshot, password.as_ref(), &kdf, random_array::<12>()?)
    }

    pub fn import_backup(
        &mut self,
        bytes: impl AsRef<[u8]>,
        password: impl AsRef<str>,
    ) -> HydraResult<()> {
        let snapshot = decode_backup(bytes.as_ref(), password.as_ref())?;
        self.apply_state_snapshot(&snapshot)?;
        self.persist()?;
        Ok(())
    }

    pub fn verify_backup(&self, bytes: impl AsRef<[u8]>) -> HydraResult<()> {
        parse_backup_outer(bytes.as_ref())
    }

    #[must_use]
    pub fn storage_status(&self) -> HydraStorageStatus {
        HydraStorageStatus {
            data_dir: self.data_dir.clone(),
            identity_count: self.identities.len(),
            contact_count: self.contacts.len(),
            session_count: self.sessions.len(),
            message_count: self.messages.len(),
            lobby_count: self.lobbies.len(),
            encrypted_state: true,
            state_generation: self.state_generation,
        }
    }

    fn empty(
        data_dir: PathBuf,
        state_key: hydra_crypto::SecretBytes<32>,
        state_kdf: PasswordKdfRecord,
    ) -> Self {
        Self {
            data_dir,
            identities: HashMap::new(),
            active_id: None,
            contacts: HashMap::new(),
            pending_offers: HashMap::new(),
            sessions: HashMap::new(),
            messages: Vec::new(),
            next_message_id: 1,
            lobbies: HashMap::new(),
            state_key,
            state_kdf,
            state_generation: 0,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn state_path(&self) -> PathBuf {
        self.data_dir.join(STATE_FILE_NAME)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn rollback_path(&self) -> PathBuf {
        self.data_dir.join(STATE_ROLLBACK_FILE_NAME)
    }

    fn load_state(&mut self) -> HydraResult<()> {
        #[cfg(target_arch = "wasm32")]
        {
            return Ok(());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = self.state_path();
            if !path.exists() {
                return Ok(());
            }
            let bytes = fs::read(path)?;
            let snapshot = decode_encrypted_state_v2(&bytes, &self.state_key)?;
            self.apply_state_snapshot(&snapshot)?;
            self.reject_state_rollback()?;
            self.write_rollback_guard()?;
            Ok(())
        }
    }

    pub(crate) fn persist(&mut self) -> HydraResult<()> {
        #[cfg(target_arch = "wasm32")]
        {
            return Ok(());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.state_generation = self.state_generation.saturating_add(1);
            let snapshot = self.encode_state_snapshot()?;
            let encrypted = encode_encrypted_state_v2(
                &snapshot,
                &self.state_key,
                &self.state_kdf,
                random_array::<12>()?,
            )?;
            write_atomic(&self.state_path(), &encrypted)?;
            self.write_rollback_guard()?;
            Ok(())
        }
    }

    fn encode_state_snapshot(&self) -> HydraResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(STATE_SNAPSHOT_MAGIC);
        out.extend_from_slice(format!("state_generation\t{}\n", self.state_generation).as_bytes());
        out.extend_from_slice(format!("next_message_id\t{}\n", self.next_message_id).as_bytes());
        for record in self.identities.values() {
            out.extend_from_slice(encode_identity_line(record).as_bytes());
            out.push(b'\n');
        }
        for contact in self.contacts.values() {
            out.extend_from_slice(encode_contact_line(contact).as_bytes());
            out.push(b'\n');
        }
        for message in &self.messages {
            out.extend_from_slice(encode_message_line(message).as_bytes());
            out.push(b'\n');
        }
        for lobby in self.lobbies.values() {
            out.extend_from_slice(encode_lobby_line(lobby).as_bytes());
            out.push(b'\n');
        }
        Ok(out)
    }

    fn apply_state_snapshot(&mut self, bytes: &[u8]) -> HydraResult<()> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| HydraMsgError::InvalidEncoding("state snapshot utf-8"))?;
        if !text.starts_with(std::str::from_utf8(STATE_SNAPSHOT_MAGIC).unwrap_or_default()) {
            return Err(HydraMsgError::InvalidEncoding("state snapshot magic"));
        }
        self.identities.clear();
        self.active_id = None;
        self.contacts.clear();
        self.pending_offers.clear();
        self.sessions.clear();
        self.messages.clear();
        self.lobbies.clear();
        self.next_message_id = 1;
        self.state_generation = 0;
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let mut parts = line.split('\t');
            match parts.next() {
                Some("state_generation") => {
                    if let Some(value) = parts.next() {
                        self.state_generation = value
                            .parse()
                            .map_err(|_| HydraMsgError::InvalidEncoding("state generation"))?;
                    }
                }
                Some("next_message_id") => {
                    if let Some(value) = parts.next() {
                        self.next_message_id = value
                            .parse()
                            .map_err(|_| HydraMsgError::InvalidEncoding("state next_message_id"))?;
                    }
                }
                Some("identity") => {
                    let record = decode_identity_line(line)?;
                    self.identities.insert(record.id, record);
                }
                Some("contact") => {
                    let contact = decode_contact_line(line)?;
                    self.contacts.insert(contact.id, contact);
                }
                Some("message") => {
                    let message = decode_message_line(line)?;
                    self.next_message_id = self.next_message_id.max(message.id.0.saturating_add(1));
                    self.messages.push(message);
                }
                Some("lobby") => {
                    let lobby = decode_lobby_line(line)?;
                    self.lobbies.insert(lobby.id, lobby);
                }
                _ => return Err(HydraMsgError::InvalidEncoding("state record kind")),
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn reject_state_rollback(&self) -> HydraResult<()> {
        let guard = self.rollback_path();
        if !guard.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(guard)?;
        let newest = text
            .trim()
            .parse::<u64>()
            .map_err(|_| HydraMsgError::InvalidEncoding("state rollback guard"))?;
        if self.state_generation < newest {
            return Err(HydraMsgError::InvalidEncoding("state rollback detected"));
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_rollback_guard(&self) -> HydraResult<()> {
        write_atomic(
            &self.rollback_path(),
            format!("{}\n", self.state_generation).as_bytes(),
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn write_atomic(path: &Path, bytes: &[u8]) -> HydraResult<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    if let Ok(file) = fs::File::open(&tmp) {
        let _ = file.sync_all();
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
