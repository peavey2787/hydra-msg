use getrandom::SysRng;
use hydra_core::{ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE, ML_KEM_SHARED_SECRET_SIZE};
use ml_kem::{
    kem::{Decapsulate, FromSeed, KeyExport},
    ml_kem_768::{DecapsulationKey, EncapsulationKey},
    MlKem768, Seed, B32,
};
use rand_core::TryRng;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, CryptoResult, SecretBytes};

/// ML-KEM secret key. The backend's `zeroize` feature clears its private
/// polynomial state, seeds, and fallback secret on drop.
pub struct MlKemDecapsulationKey(DecapsulationKey);

#[derive(Clone)]
pub struct MlKemEncapsulationKey(EncapsulationKey);

pub struct MlKemKeyPair {
    pub decapsulation_key: MlKemDecapsulationKey,
    pub encapsulation_key: MlKemEncapsulationKey,
}

impl MlKemKeyPair {
    pub fn generate() -> CryptoResult<Self> {
        // FIPS 203 d and z are separate independent draws.
        let mut seed = Zeroizing::new([0_u8; 64]);
        SysRng
            .try_fill_bytes(&mut seed[..32])
            .map_err(|_| CryptoError::EntropyUnavailable)?;
        SysRng
            .try_fill_bytes(&mut seed[32..])
            .map_err(|_| CryptoError::EntropyUnavailable)?;
        let mut seed_array: Seed = (*seed).into();
        let (decapsulation_key, encapsulation_key) = MlKem768::from_seed(&seed_array);
        seed_array.as_mut_slice().zeroize();
        Ok(Self {
            decapsulation_key: MlKemDecapsulationKey(decapsulation_key),
            encapsulation_key: MlKemEncapsulationKey(encapsulation_key),
        })
    }
}

impl MlKemEncapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != ML_KEM_768_EK_SIZE {
            return Err(CryptoError::InvalidLength {
                field: "ML-KEM-768 encapsulation key",
                expected: ML_KEM_768_EK_SIZE,
                actual: bytes.len(),
            });
        }
        let mut encoded = ml_kem::kem::Key::<EncapsulationKey>::default();
        encoded.copy_from_slice(bytes);
        EncapsulationKey::new(&encoded)
            .map(Self)
            .map_err(|_| CryptoError::InvalidEncoding("ML-KEM-768 encapsulation key"))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; ML_KEM_768_EK_SIZE] {
        let encoded = self.0.to_bytes();
        let mut output = [0_u8; ML_KEM_768_EK_SIZE];
        output.copy_from_slice(encoded.as_ref());
        output
    }

    pub fn encapsulate(&self) -> CryptoResult<([u8; ML_KEM_768_CT_SIZE], SecretBytes<32>)> {
        // Fill before calling the deterministic primitive so RNG failure
        // returns without producing ciphertext or shared-secret output.
        let mut entropy = B32::default();
        SysRng
            .try_fill_bytes(entropy.as_mut_slice())
            .map_err(|_| CryptoError::EntropyUnavailable)?;
        let (ciphertext, mut shared_secret) = self.0.encapsulate_deterministic(&entropy);
        entropy.as_mut_slice().zeroize();

        let mut encoded_ciphertext = [0_u8; ML_KEM_768_CT_SIZE];
        encoded_ciphertext.copy_from_slice(ciphertext.as_ref());
        let mut shared_secret_output = [0_u8; ML_KEM_SHARED_SECRET_SIZE];
        shared_secret_output.copy_from_slice(shared_secret.as_ref());
        shared_secret.as_mut_slice().zeroize();
        Ok((encoded_ciphertext, SecretBytes::new(shared_secret_output)))
    }
}

impl MlKemDecapsulationKey {
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<SecretBytes<32>> {
        if ciphertext.len() != ML_KEM_768_CT_SIZE {
            return Err(CryptoError::InvalidLength {
                field: "ML-KEM-768 ciphertext",
                expected: ML_KEM_768_CT_SIZE,
                actual: ciphertext.len(),
            });
        }
        let mut encoded = ml_kem::kem::Ciphertext::<MlKem768>::default();
        encoded.copy_from_slice(ciphertext);
        let mut shared = self.0.decapsulate(&encoded);
        let mut shared_output = [0_u8; ML_KEM_SHARED_SECRET_SIZE];
        shared_output.copy_from_slice(shared.as_ref());
        shared.as_mut_slice().zeroize();
        Ok(SecretBytes::new(shared_output))
    }
}
