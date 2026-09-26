use getrandom::SysRng;
use hydra_core::{ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE, TRANSCRIPT_HASH_SIZE};
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, Verifier, VerifyingKey,
};
use rand_core::{TryCryptoRng, TryRng};
use zeroize::{Zeroize, Zeroizing};

use crate::{error::exact_array, CryptoError, CryptoResult};

/// ML-DSA signing key. The backend `zeroize` feature clears the seed and
/// expanded secret state on drop.
pub struct MlDsaSigningKey(SigningKey<MlDsa65>);

#[derive(Clone, Debug, PartialEq)]
pub struct MlDsaVerificationKey(VerifyingKey<MlDsa65>);

pub struct MlDsaKeyPair {
    pub signing_key: MlDsaSigningKey,
    pub verification_key: MlDsaVerificationKey,
}

impl MlDsaKeyPair {
    pub fn generate() -> CryptoResult<Self> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        SysRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| CryptoError::EntropyUnavailable)?;
        Self::from_seed(*seed)
    }

    /// Reconstructs an ML-DSA-65 keypair from a 32-byte seed.
    ///
    /// This is used by encrypted application identity stores. The seed must
    /// never be written to disk except inside an authenticated encrypted
    /// store.
    pub fn from_seed(seed: [u8; 32]) -> CryptoResult<Self> {
        let mut seed = Zeroizing::new(seed);
        let mut seed_array: ml_dsa::Seed = (*seed).into();
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_array);
        seed_array.as_mut_slice().zeroize();
        seed.zeroize();
        let verification_key = signing_key.verifying_key();
        Ok(Self {
            signing_key: MlDsaSigningKey(signing_key),
            verification_key: MlDsaVerificationKey(verification_key),
        })
    }
}

impl MlDsaSigningKey {
    pub fn sign_digest(&self, digest: &[u8]) -> CryptoResult<[u8; ML_DSA_65_SIG_SIZE]> {
        self.sign_digest_with_rng(digest, &mut SysRng)
    }

    /// Signing core with an injectable entropy source, so RNG failure is
    /// testable: it must return `EntropyUnavailable` and produce no signature.
    fn sign_digest_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        digest: &[u8],
        rng: &mut R,
    ) -> CryptoResult<[u8; ML_DSA_65_SIG_SIZE]> {
        let digest = exact_array::<TRANSCRIPT_HASH_SIZE>("ML-DSA-65 digest", digest)?;
        let signature = self
            .0
            .expanded_key()
            .sign_randomized(&digest, &[], rng)
            .map_err(|_| CryptoError::EntropyUnavailable)?;
        let encoded = signature.encode();
        let mut output = [0_u8; ML_DSA_65_SIG_SIZE];
        output.copy_from_slice(encoded.as_ref());
        Ok(output)
    }
}

impl MlDsaVerificationKey {
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != ML_DSA_65_VK_SIZE {
            return Err(CryptoError::InvalidLength {
                field: "ML-DSA-65 verification key",
                expected: ML_DSA_65_VK_SIZE,
                actual: bytes.len(),
            });
        }
        let mut encoded = EncodedVerifyingKey::<MlDsa65>::default();
        encoded.copy_from_slice(bytes);
        Ok(Self(VerifyingKey::decode(&encoded)))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; ML_DSA_65_VK_SIZE] {
        let encoded = self.0.encode();
        let mut output = [0_u8; ML_DSA_65_VK_SIZE];
        output.copy_from_slice(encoded.as_ref());
        output
    }

    pub fn verify_digest(&self, digest: &[u8], signature: &[u8]) -> CryptoResult<()> {
        let digest = exact_array::<TRANSCRIPT_HASH_SIZE>("ML-DSA-65 digest", digest)?;
        if signature.len() != ML_DSA_65_SIG_SIZE {
            return Err(CryptoError::InvalidLength {
                field: "ML-DSA-65 signature",
                expected: ML_DSA_65_SIG_SIZE,
                actual: signature.len(),
            });
        }
        let signature = Signature::<MlDsa65>::try_from(signature)
            .map_err(|_| CryptoError::InvalidEncoding("ML-DSA-65 signature"))?;
        self.0
            .verify(&digest, &signature)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng::FailingRng;

    #[test]
    fn signing_with_unavailable_entropy_fails_without_a_signature() {
        let pair = MlDsaKeyPair::from_seed([7; 32]).unwrap();
        let result = pair
            .signing_key
            .sign_digest_with_rng(&[1; TRANSCRIPT_HASH_SIZE], &mut FailingRng);
        assert!(matches!(result, Err(CryptoError::EntropyUnavailable)));
    }
}
