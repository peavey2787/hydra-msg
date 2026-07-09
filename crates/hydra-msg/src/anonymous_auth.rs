use crate::{codec::*, Hydra, HydraMsgError, HydraResult};
use hydra_core::HASH_SIZE;

/// One-time anonymous authorization policy.
///
/// The scope and action are authorization context, not contact identity. Apps
/// should use fresh, app-defined scopes for unlinkable chats, lobbies, mailboxes,
/// or relay actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraAnonymousAuthPolicy {
    pub(crate) scope: String,
    pub(crate) action: String,
    pub(crate) expires_at_unix_seconds: Option<u64>,
}

impl HydraAnonymousAuthPolicy {
    #[must_use]
    pub fn new(scope: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            action: action.into(),
            expires_at_unix_seconds: None,
        }
    }

    #[must_use]
    pub fn with_expiry(mut self, expires_at_unix_seconds: u64) -> Self {
        self.expires_at_unix_seconds = Some(expires_at_unix_seconds);
        self
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> Option<u64> {
        self.expires_at_unix_seconds
    }
}

/// Opaque one-time anonymous authorization token.
///
/// This is a bearer-token stopgap for current app flows. It proves possession of
/// a random token minted by the verifier's issuer secret, not possession of a
/// contact identity. Stronger anonymous-but-authorized designs should replace or
/// wrap this with blind credentials or zero-knowledge proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraAnonymousAuthToken(pub(crate) Vec<u8>);

impl HydraAnonymousAuthToken {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HydraAnonymousAuthToken {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// One-time token nullifier used by verifiers to reject replay/double-spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HydraAnonymousAuthNullifier(pub(crate) [u8; HASH_SIZE]);

impl HydraAnonymousAuthNullifier {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
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

/// Authorization result for an accepted anonymous token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydraAnonymousAuthGrant {
    pub(crate) policy: HydraAnonymousAuthPolicy,
    pub(crate) nullifier: HydraAnonymousAuthNullifier,
}

impl HydraAnonymousAuthGrant {
    #[must_use]
    pub fn policy(&self) -> &HydraAnonymousAuthPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn nullifier(&self) -> HydraAnonymousAuthNullifier {
        self.nullifier
    }
}

impl Hydra {
    pub fn issue_anonymous_auth_token(
        &mut self,
        policy: HydraAnonymousAuthPolicy,
    ) -> HydraResult<HydraAnonymousAuthToken> {
        validate_anonymous_auth_policy(&policy)?;
        let nonce = random_array::<32>()?;
        let tag = anonymous_auth_token_tag(&self.anonymous_auth_secret, &policy, &nonce);
        let token = HydraAnonymousAuthToken(encode_anonymous_auth_token(&policy, nonce, tag));
        self.persist()?;
        Ok(token)
    }

    pub fn anonymous_auth_nullifier(
        &self,
        token: impl AsRef<[u8]>,
    ) -> HydraResult<HydraAnonymousAuthNullifier> {
        let parsed = decode_anonymous_auth_token(token.as_ref())?;
        verify_anonymous_auth_token_tag(&self.anonymous_auth_secret, &parsed)?;
        Ok(anonymous_auth_token_nullifier(
            &self.anonymous_auth_secret,
            &parsed,
        ))
    }

    pub fn accept_anonymous_auth_token(
        &mut self,
        token: impl AsRef<[u8]>,
        expected_scope: impl AsRef<str>,
        expected_action: impl AsRef<str>,
        now_unix_seconds: u64,
    ) -> HydraResult<HydraAnonymousAuthGrant> {
        let parsed = decode_anonymous_auth_token(token.as_ref())?;
        verify_anonymous_auth_token_tag(&self.anonymous_auth_secret, &parsed)?;
        require_expected_policy(
            &parsed.policy,
            expected_scope.as_ref(),
            expected_action.as_ref(),
        )?;
        reject_expired_policy(&parsed.policy, now_unix_seconds)?;
        let nullifier = anonymous_auth_token_nullifier(&self.anonymous_auth_secret, &parsed);
        self.reject_spent_anonymous_auth_nullifier(nullifier)?;
        self.anonymous_auth_spent.push(nullifier);
        self.persist()?;
        Ok(HydraAnonymousAuthGrant {
            policy: parsed.policy,
            nullifier,
        })
    }

    pub fn revoke_anonymous_auth_token(
        &mut self,
        token: impl AsRef<[u8]>,
        expected_scope: impl AsRef<str>,
        expected_action: impl AsRef<str>,
    ) -> HydraResult<HydraAnonymousAuthNullifier> {
        let parsed = decode_anonymous_auth_token(token.as_ref())?;
        verify_anonymous_auth_token_tag(&self.anonymous_auth_secret, &parsed)?;
        require_expected_policy(
            &parsed.policy,
            expected_scope.as_ref(),
            expected_action.as_ref(),
        )?;
        let nullifier = anonymous_auth_token_nullifier(&self.anonymous_auth_secret, &parsed);
        if !self.anonymous_auth_spent.contains(&nullifier) {
            self.anonymous_auth_spent.push(nullifier);
            self.persist()?;
        }
        Ok(nullifier)
    }

    fn reject_spent_anonymous_auth_nullifier(
        &self,
        nullifier: HydraAnonymousAuthNullifier,
    ) -> HydraResult<()> {
        if self.anonymous_auth_spent.contains(&nullifier) {
            return Err(HydraMsgError::InvalidInput(
                "anonymous authorization token already spent",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_anonymous_auth_policy(policy: &HydraAnonymousAuthPolicy) -> HydraResult<()> {
    validate_anonymous_auth_field(&policy.scope, "anonymous authorization scope")?;
    validate_anonymous_auth_field(&policy.action, "anonymous authorization action")?;
    Ok(())
}

fn validate_anonymous_auth_field(value: &str, name: &'static str) -> HydraResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(HydraMsgError::InvalidInput(name));
    }
    if trimmed.len() > 256 {
        return Err(HydraMsgError::InvalidInput(name));
    }
    Ok(())
}

fn require_expected_policy(
    policy: &HydraAnonymousAuthPolicy,
    expected_scope: &str,
    expected_action: &str,
) -> HydraResult<()> {
    if policy.scope != expected_scope || policy.action != expected_action {
        return Err(HydraMsgError::InvalidInput(
            "anonymous authorization policy mismatch",
        ));
    }
    Ok(())
}

fn reject_expired_policy(
    policy: &HydraAnonymousAuthPolicy,
    now_unix_seconds: u64,
) -> HydraResult<()> {
    if let Some(expires_at) = policy.expires_at_unix_seconds {
        if now_unix_seconds > expires_at {
            return Err(HydraMsgError::InvalidInput(
                "anonymous authorization token expired",
            ));
        }
    }
    Ok(())
}
