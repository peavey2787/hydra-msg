use hydra_app_core::{ChatShell, IdentityVault, MESSAGE_STORE_FILE};

use crate::{
    config::AppConfig,
    contacts::ContactBook,
    secrets::{load_storage_secret, AppStorageSecret},
};

pub struct AppContext {
    pub config: AppConfig,
    storage_secret: AppStorageSecret,
}

impl AppContext {
    pub fn load() -> Result<Self, String> {
        let config = AppConfig::load_or_default()?;
        let storage_secret = load_storage_secret(&config.data_dir)?;
        Ok(Self {
            config,
            storage_secret,
        })
    }

    #[must_use]
    pub fn storage_secret(&self) -> &[u8; 32] {
        self.storage_secret.expose_secret()
    }

    pub fn vault(&self) -> Result<IdentityVault, String> {
        IdentityVault::open(&self.config.data_dir).map_err(|error| error.to_string())
    }

    pub fn contact_book(&self) -> Result<ContactBook, String> {
        ContactBook::load(&self.config.data_dir, self.storage_secret())
    }

    pub fn chat_shell(&self) -> Result<ChatShell, String> {
        ChatShell::open_or_create(
            self.config.data_dir.join(MESSAGE_STORE_FILE),
            self.storage_secret(),
        )
        .map_err(|error| error.to_string())
    }
}
