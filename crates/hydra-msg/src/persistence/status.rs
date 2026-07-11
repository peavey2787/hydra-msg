use crate::Hydra;
use std::path::PathBuf;

/// Redacted local storage summary safe for normal production surfaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraStorageStatus {
    pub data_dir: PathBuf,
    pub encrypted_state: bool,
}

/// Debug-only storage summary for tests and diagnostics.
///
/// Applications must not log or expose this in production telemetry: counts and
/// generations are local metadata about the user's profile shape and activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraStorageDebugStatus {
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
    #[must_use]
    pub fn storage_status(&self) -> HydraStorageStatus {
        HydraStorageStatus {
            data_dir: self.data_dir.clone(),
            encrypted_state: true,
        }
    }

    #[must_use]
    pub fn storage_debug_status(&self) -> HydraStorageDebugStatus {
        HydraStorageDebugStatus {
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
}
