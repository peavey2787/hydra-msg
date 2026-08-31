use std::{fs, path::PathBuf, sync::Mutex};

use hydra_msg::{Hydra, HydraAnonymousAuthPolicy};

use crate::json;

type AuthResult<T> = Result<T, String>;

pub(crate) struct DemoAuthService {
    hydra: Mutex<Hydra>,
}

impl DemoAuthService {
    pub(crate) fn new() -> AuthResult<Self> {
        let data_dir = demo_data_dir();
        fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
        let hydra = Hydra::open(data_dir, "hydra-gui-demo-auth-state")
            .map_err(|error| error.to_string())?;
        Ok(Self {
            hydra: Mutex::new(hydra),
        })
    }

    pub(crate) fn issue(
        &self,
        scope: &str,
        action: &str,
        expiry: Option<u64>,
    ) -> AuthResult<Vec<u8>> {
        let mut policy = HydraAnonymousAuthPolicy::new(scope, action);
        if let Some(expiry) = expiry {
            policy = policy.with_expiry(expiry);
        }
        self.lock()?
            .issue_anonymous_auth_token(policy)
            .map(|token| token.into_bytes())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn nullifier(&self, token: &[u8]) -> AuthResult<String> {
        self.lock()?
            .anonymous_auth_nullifier(token)
            .map(|value| value.hex())
            .map_err(|error| error.to_string())
    }

    pub(crate) fn accept(
        &self,
        token: &[u8],
        scope: &str,
        action: &str,
        now: u64,
    ) -> AuthResult<String> {
        let grant = self
            .lock()?
            .accept_anonymous_auth_token(token, scope, action, now)
            .map_err(|error| error.to_string())?;
        let expiry = grant
            .policy()
            .expires_at_unix_seconds()
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        Ok(format!(
            "{{\"scope\":{},\"action\":{},\"expiresAtUnixSeconds\":{},\"nullifier\":{}}}",
            json::string(grant.policy().scope()),
            json::string(grant.policy().action()),
            expiry,
            json::string(&grant.nullifier().hex()),
        ))
    }

    pub(crate) fn revoke(&self, token: &[u8], scope: &str, action: &str) -> AuthResult<String> {
        self.lock()?
            .revoke_anonymous_auth_token(token, scope, action)
            .map(|value| value.hex())
            .map_err(|error| error.to_string())
    }

    fn lock(&self) -> AuthResult<std::sync::MutexGuard<'_, Hydra>> {
        self.hydra
            .lock()
            .map_err(|_| "anonymous-auth demo lock is poisoned".to_owned())
    }
}

fn demo_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/hydra-gui-demo-auth")
}
