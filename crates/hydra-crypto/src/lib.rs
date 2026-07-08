//! Fixed-suite cryptographic backend abstraction and RustCrypto adapter.
//!
//! This M3 adapter provides executable reference behavior. It is not the
//! pinned OpenSSL release backend and is not independent interoperability,
//! platform, or constant-time evidence.

#![forbid(unsafe_code)]

mod aead;
mod backend;
mod error;
mod hash;
mod kdf;
mod mac;
mod ml_dsa;
mod ml_kem;
mod secret;
mod x25519;

pub use backend::{CryptoBackend, RustCryptoBackend};
pub use error::{CryptoError, CryptoResult};
pub use ml_dsa::{MlDsaKeyPair, MlDsaSigningKey, MlDsaVerificationKey};
pub use ml_kem::{MlKemDecapsulationKey, MlKemEncapsulationKey, MlKemKeyPair};
pub use secret::SecretBytes;
pub use x25519::X25519SecretKey;
