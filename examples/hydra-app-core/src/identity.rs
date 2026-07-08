use hydra_core::{
    types::{Epoch, GroupId, IdentityFingerprint, IdentityPublicKey},
    ML_DSA_65_SIG_SIZE,
};
use hydra_crypto::{
    CryptoBackend, MlDsaKeyPair, MlDsaSigningKey, MlDsaVerificationKey, RustCryptoBackend,
};
use hydra_group::{identity_fingerprint, member_id, MemberId};

use crate::{AppError, AppResult};

/// Local app identity. The signing key is intentionally private to this crate.
pub struct AppIdentity {
    keypair: MlDsaKeyPair,
    fingerprint: IdentityFingerprint,
}

/// Public identity material safe to store in rosters, profiles, and contacts.
#[derive(Clone, Debug, PartialEq)]
pub struct PublicIdentity {
    verification_key: MlDsaVerificationKey,
    public_key: IdentityPublicKey,
    fingerprint: IdentityFingerprint,
}

impl AppIdentity {
    pub fn generate() -> AppResult<Self> {
        let keypair = RustCryptoBackend::mldsa65_generate()?;
        let fingerprint = identity_fingerprint(&keypair.verification_key);
        Ok(Self {
            keypair,
            fingerprint,
        })
    }

    pub(crate) fn from_seed(seed: [u8; 32]) -> AppResult<Self> {
        let keypair = MlDsaKeyPair::from_seed(seed)?;
        let fingerprint = identity_fingerprint(&keypair.verification_key);
        Ok(Self {
            keypair,
            fingerprint,
        })
    }

    #[must_use]
    pub fn public_identity(&self) -> PublicIdentity {
        PublicIdentity::from_verification_key(self.keypair.verification_key.clone())
    }

    #[must_use]
    pub const fn fingerprint(&self) -> IdentityFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn member_id(&self, group_id: GroupId, joined_epoch: Epoch) -> MemberId {
        member_id(group_id, self.fingerprint, joined_epoch)
    }

    pub(crate) fn signing_key(&self) -> &MlDsaSigningKey {
        &self.keypair.signing_key
    }

    pub(crate) fn sign_backup_checkpoint_digest(
        &self,
        digest: &[u8; 64],
    ) -> AppResult<[u8; ML_DSA_65_SIG_SIZE]> {
        self.signing_key()
            .sign_digest(digest)
            .map_err(AppError::from)
    }
}

impl PublicIdentity {
    #[must_use]
    pub fn from_verification_key(verification_key: MlDsaVerificationKey) -> Self {
        let bytes = verification_key.to_bytes();
        let fingerprint = identity_fingerprint(&verification_key);
        Self {
            verification_key,
            public_key: IdentityPublicKey(bytes),
            fingerprint,
        }
    }

    pub fn from_public_key(public_key: IdentityPublicKey) -> AppResult<Self> {
        let verification_key = MlDsaVerificationKey::from_bytes(&public_key.0)?;
        Ok(Self::from_verification_key(verification_key))
    }

    #[must_use]
    pub const fn fingerprint(&self) -> IdentityFingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn public_key(&self) -> &IdentityPublicKey {
        &self.public_key
    }

    #[must_use]
    pub fn verification_key_for_group(&self) -> MlDsaVerificationKey {
        self.verification_key.clone()
    }

    pub(crate) fn verify_backup_checkpoint_digest(
        &self,
        digest: &[u8; 64],
        signature: &[u8],
    ) -> AppResult<()> {
        self.verification_key
            .verify_digest(digest, signature)
            .map_err(AppError::from)
    }

    #[must_use]
    pub fn member_id(&self, group_id: GroupId, joined_epoch: Epoch) -> MemberId {
        member_id(group_id, self.fingerprint, joined_epoch)
    }
}

impl TryFrom<IdentityPublicKey> for PublicIdentity {
    type Error = AppError;

    fn try_from(value: IdentityPublicKey) -> Result<Self, Self::Error> {
        Self::from_public_key(value)
    }
}
