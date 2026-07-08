use hydra_core::{ML_DSA_65_SIG_SIZE, ML_KEM_768_CT_SIZE, SUITE_ID};
use zeroize::Zeroizing;

use crate::{
    aead, hash, kdf, mac, CryptoResult, MlDsaKeyPair, MlDsaSigningKey, MlDsaVerificationKey,
    MlKemDecapsulationKey, MlKemEncapsulationKey, MlKemKeyPair, SecretBytes, X25519SecretKey,
};

/// Fixed-suite backend contract.
///
/// There is deliberately no suite-selection argument. Supporting different
/// algorithms requires a different authenticated protocol suite.
pub trait CryptoBackend {
    const NAME: &'static str;
    const SUITE_ID: [u8; 16];

    fn sha3_256(input: &[u8]) -> [u8; 32];
    fn sha3_512(input: &[u8]) -> [u8; 64];
    fn hmac_sha3_256(key: &SecretBytes<32>, input: &[u8]) -> [u8; 32];
    fn verify_hmac_sha3_256(
        key: &SecretBytes<32>,
        input: &[u8],
        expected: &[u8],
    ) -> CryptoResult<()>;
    fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> SecretBytes<32>;
    fn hkdf_expand(
        pseudorandom_key: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> CryptoResult<Zeroizing<Vec<u8>>>;
    fn aead_seal(
        key: &SecretBytes<32>,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>>;
    fn aead_open(
        key: &SecretBytes<32>,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> CryptoResult<Zeroizing<Vec<u8>>>;
    fn x25519_generate() -> CryptoResult<X25519SecretKey>;
    fn x25519_diffie_hellman(
        key: &X25519SecretKey,
        peer_public_key: &[u8],
    ) -> CryptoResult<SecretBytes<32>>;
    fn mlkem768_generate() -> CryptoResult<MlKemKeyPair>;
    fn mlkem768_encapsulate(
        key: &MlKemEncapsulationKey,
    ) -> CryptoResult<([u8; ML_KEM_768_CT_SIZE], SecretBytes<32>)>;
    fn mlkem768_decapsulate(
        key: &MlKemDecapsulationKey,
        ciphertext: &[u8],
    ) -> CryptoResult<SecretBytes<32>>;
    fn mldsa65_generate() -> CryptoResult<MlDsaKeyPair>;
    fn mldsa65_sign(key: &MlDsaSigningKey, digest: &[u8])
        -> CryptoResult<[u8; ML_DSA_65_SIG_SIZE]>;
    fn mldsa65_verify(
        key: &MlDsaVerificationKey,
        digest: &[u8],
        signature: &[u8],
    ) -> CryptoResult<()>;
}

pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    const NAME: &'static str = "RustCrypto candidate adapter";
    const SUITE_ID: [u8; 16] = SUITE_ID;

    fn sha3_256(input: &[u8]) -> [u8; 32] {
        hash::sha3_256(input)
    }

    fn sha3_512(input: &[u8]) -> [u8; 64] {
        hash::sha3_512(input)
    }

    fn hmac_sha3_256(key: &SecretBytes<32>, input: &[u8]) -> [u8; 32] {
        mac::hmac_sha3_256(key, input)
    }

    fn verify_hmac_sha3_256(
        key: &SecretBytes<32>,
        input: &[u8],
        expected: &[u8],
    ) -> CryptoResult<()> {
        mac::verify_hmac_sha3_256(key, input, expected)
    }

    fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> SecretBytes<32> {
        kdf::hkdf_extract(salt, input_key_material)
    }

    fn hkdf_expand(
        pseudorandom_key: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> CryptoResult<Zeroizing<Vec<u8>>> {
        kdf::hkdf_expand(pseudorandom_key, info, output_length)
    }

    fn aead_seal(
        key: &SecretBytes<32>,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        aead::seal(key, nonce, aad, plaintext)
    }

    fn aead_open(
        key: &SecretBytes<32>,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> CryptoResult<Zeroizing<Vec<u8>>> {
        aead::open(key, nonce, aad, ciphertext_and_tag)
    }

    fn x25519_generate() -> CryptoResult<X25519SecretKey> {
        X25519SecretKey::generate()
    }

    fn x25519_diffie_hellman(
        key: &X25519SecretKey,
        peer_public_key: &[u8],
    ) -> CryptoResult<SecretBytes<32>> {
        key.diffie_hellman(peer_public_key)
    }

    fn mlkem768_generate() -> CryptoResult<MlKemKeyPair> {
        MlKemKeyPair::generate()
    }

    fn mlkem768_encapsulate(
        key: &MlKemEncapsulationKey,
    ) -> CryptoResult<([u8; ML_KEM_768_CT_SIZE], SecretBytes<32>)> {
        key.encapsulate()
    }

    fn mlkem768_decapsulate(
        key: &MlKemDecapsulationKey,
        ciphertext: &[u8],
    ) -> CryptoResult<SecretBytes<32>> {
        key.decapsulate(ciphertext)
    }

    fn mldsa65_generate() -> CryptoResult<MlDsaKeyPair> {
        MlDsaKeyPair::generate()
    }

    fn mldsa65_sign(
        key: &MlDsaSigningKey,
        digest: &[u8],
    ) -> CryptoResult<[u8; ML_DSA_65_SIG_SIZE]> {
        key.sign_digest(digest)
    }

    fn mldsa65_verify(
        key: &MlDsaVerificationKey,
        digest: &[u8],
        signature: &[u8],
    ) -> CryptoResult<()> {
        key.verify_digest(digest, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;

    #[test]
    fn hash_hmac_hkdf_and_aead_are_executable() {
        assert_eq!(
            hex::encode(RustCryptoBackend::sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex::encode(RustCryptoBackend::sha3_512(b"")),
            concat!(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6",
                "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )
        );

        let key = SecretBytes::new([0x42; 32]);
        let tag = RustCryptoBackend::hmac_sha3_256(&key, b"message");
        assert_eq!(
            hex::encode(tag),
            "0bbbae326662025a1ecee864ece37ecee10447386eb171e42f8a0ad982f7f647"
        );
        RustCryptoBackend::verify_hmac_sha3_256(&key, b"message", &tag).unwrap();
        assert_eq!(
            RustCryptoBackend::verify_hmac_sha3_256(&key, b"changed", &tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let prk = RustCryptoBackend::hkdf_extract(b"salt", b"input key material");
        assert_eq!(
            hex::encode(prk.expose_secret()),
            "d9f8c69c7d8d4d172bb29b7bfb34f4f9d191cd4640057ffab914711cb2a44060"
        );
        let derived = RustCryptoBackend::hkdf_expand(prk.expose_secret(), b"context", 32).unwrap();
        assert_eq!(
            hex::encode(&*derived),
            "18a8c06a5228b7275f03cb21bcfbc91d1c1ae5d31519072dd6d15dd0ac93d35b"
        );

        let nonce = [0_u8; 12];
        let mut ciphertext =
            RustCryptoBackend::aead_seal(&key, &nonce, b"aad", b"plaintext").unwrap();
        let plaintext = RustCryptoBackend::aead_open(&key, &nonce, b"aad", &ciphertext).unwrap();
        assert_eq!(&*plaintext, b"plaintext");
        ciphertext[0] ^= 1;
        assert!(matches!(
            RustCryptoBackend::aead_open(&key, &nonce, b"aad", &ciphertext),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn x25519_agrees_and_rejects_all_zero() {
        let alice = RustCryptoBackend::x25519_generate().unwrap();
        let bob = RustCryptoBackend::x25519_generate().unwrap();
        let alice_shared =
            RustCryptoBackend::x25519_diffie_hellman(&alice, &bob.public_key()).unwrap();
        let bob_shared =
            RustCryptoBackend::x25519_diffie_hellman(&bob, &alice.public_key()).unwrap();
        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
        assert!(matches!(
            RustCryptoBackend::x25519_diffie_hellman(&alice, &[0_u8; 32]),
            Err(CryptoError::WeakPublicKey)
        ));
    }

    #[test]
    fn mlkem_round_trip_and_implicit_rejection_are_executable() {
        let pair = RustCryptoBackend::mlkem768_generate().unwrap();
        let encoded_key = pair.encapsulation_key.to_bytes();
        let parsed_key = MlKemEncapsulationKey::from_bytes(&encoded_key).unwrap();
        let (ciphertext, sent) = RustCryptoBackend::mlkem768_encapsulate(&parsed_key).unwrap();
        let received =
            RustCryptoBackend::mlkem768_decapsulate(&pair.decapsulation_key, &ciphertext).unwrap();
        assert_eq!(sent.expose_secret(), received.expose_secret());

        let mut mutated = ciphertext;
        mutated[0] ^= 1;
        let rejected =
            RustCryptoBackend::mlkem768_decapsulate(&pair.decapsulation_key, &mutated).unwrap();
        assert_ne!(sent.expose_secret(), rejected.expose_secret());
    }

    #[test]
    fn mldsa_round_trip_and_malformed_rejection_are_executable() {
        let pair = RustCryptoBackend::mldsa65_generate().unwrap();
        let encoded_key = pair.verification_key.to_bytes();
        let parsed_key = MlDsaVerificationKey::from_bytes(&encoded_key).unwrap();
        let digest = RustCryptoBackend::sha3_512(b"message");
        let signature = RustCryptoBackend::mldsa65_sign(&pair.signing_key, &digest).unwrap();
        RustCryptoBackend::mldsa65_verify(&parsed_key, &digest, &signature).unwrap();

        let mut mutated = signature;
        mutated[0] ^= 1;
        assert!(RustCryptoBackend::mldsa65_verify(&parsed_key, &digest, &mutated).is_err());
    }

    #[test]
    fn external_byte_interfaces_reject_wrong_sizes() {
        assert!(matches!(
            X25519SecretKey::from_bytes(&[0_u8; 31]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            MlKemEncapsulationKey::from_bytes(&[0_u8; 1183]),
            Err(CryptoError::InvalidLength { .. })
        ));
        let kem = RustCryptoBackend::mlkem768_generate().unwrap();
        assert!(matches!(
            RustCryptoBackend::mlkem768_decapsulate(
                &kem.decapsulation_key,
                &[0_u8; ML_KEM_768_CT_SIZE - 1]
            ),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            MlDsaVerificationKey::from_bytes(&[0_u8; hydra_core::ML_DSA_65_VK_SIZE - 1]),
            Err(CryptoError::InvalidLength { .. })
        ));
        let dsa = RustCryptoBackend::mldsa65_generate().unwrap();
        assert!(matches!(
            dsa.verification_key
                .verify_digest(&[0_u8; 63], &[0_u8; ML_DSA_65_SIG_SIZE]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            dsa.verification_key
                .verify_digest(&[0_u8; 64], &[0_u8; ML_DSA_65_SIG_SIZE - 1]),
            Err(CryptoError::InvalidLength { .. })
        ));
        let key = SecretBytes::new([0_u8; 32]);
        assert!(matches!(
            RustCryptoBackend::aead_seal(&key, &[0_u8; 11], b"", b""),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            RustCryptoBackend::aead_open(&key, &[0_u8; 12], b"", &[0_u8; 15]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            RustCryptoBackend::verify_hmac_sha3_256(&key, b"", &[0_u8; 31]),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            RustCryptoBackend::hkdf_expand(&[0_u8; 31], b"", 32),
            Err(CryptoError::InvalidLength { .. })
        ));
        assert!(matches!(
            RustCryptoBackend::hkdf_expand(&[0_u8; 32], b"", 255 * 32 + 1),
            Err(CryptoError::OutputTooLong)
        ));
        let x25519 = RustCryptoBackend::x25519_generate().unwrap();
        assert!(matches!(
            RustCryptoBackend::x25519_diffie_hellman(&x25519, &[0_u8; 31]),
            Err(CryptoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn suite_is_compile_time_fixed() {
        assert_eq!(RustCryptoBackend::SUITE_ID, hydra_core::SUITE_ID);
    }
}
