use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use hydra_app_core::{IdentityUnlockSession, MessageStore};

use crate::secrets::load_storage_secret;

#[derive(Clone, Default)]
pub(crate) struct GuiAppState {
    identity_session: Arc<Mutex<IdentityUnlockSession>>,
}

impl GuiAppState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn lock_identity_session(
        &self,
    ) -> Result<MutexGuard<'_, IdentityUnlockSession>, String> {
        self.identity_session
            .lock()
            .map_err(|_| "identity unlock session is unavailable".to_owned())
    }
}

pub(crate) fn message_stats(path: &Path, data_dir: &Path) -> MessageStats {
    if !path.exists() {
        return MessageStats {
            conversations: 0,
            messages: 0,
            status: "not created yet".to_owned(),
        };
    }
    let secret = match load_storage_secret(data_dir) {
        Ok(secret) => secret,
        Err(error) => {
            return MessageStats {
                conversations: 0,
                messages: 0,
                status: format!("storage secret unavailable: {error}"),
            };
        }
    };
    match MessageStore::load(path, secret.expose_secret()) {
        Ok(store) => MessageStats {
            conversations: store.conversations().len(),
            messages: store.messages().len(),
            status: "loaded".to_owned(),
        },
        Err(error) => MessageStats {
            conversations: 0,
            messages: 0,
            status: format!("locked or unreadable: {:?}", error.class()),
        },
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MessageStats {
    pub(crate) conversations: usize,
    pub(crate) messages: usize,
    pub(crate) status: String,
}
