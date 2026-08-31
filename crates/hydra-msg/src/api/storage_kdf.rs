use crate::{persistence::encrypted_snapshot, Hydra, HydraMsgError, HydraResult};

impl Hydra {
    pub(crate) fn prepare_state_kdf_upgrade(&mut self, state_password: &str) -> HydraResult<()> {
        let new_kdf = encrypted_snapshot::new_state_kdf()?;
        let new_key = encrypted_snapshot::derive_state_key(state_password, &new_kdf)?;
        self.state_kdf = new_kdf;
        self.state_key = new_key;
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn upgrade_state_kdf(&mut self, state_password: &str) -> HydraResult<()> {
        let previous_kdf = self.state_kdf.clone();
        let previous_key = encrypted_snapshot::derive_state_key(state_password, &previous_kdf)?;
        self.prepare_state_kdf_upgrade(state_password)?;
        if let Err(error) = self.persist() {
            self.state_kdf = previous_kdf;
            self.state_key = previous_key;
            return Err(error);
        }
        Ok(())
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
            return Err(HydraMsgError::InvalidPassword);
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
}
