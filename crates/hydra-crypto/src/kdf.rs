use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;

use crate::{error::exact_array, CryptoError, CryptoResult, SecretBytes};

pub fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> SecretBytes<32> {
    let (prk, _) = Hkdf::<Sha3_256>::extract(Some(salt), input_key_material);
    SecretBytes::new(prk.into())
}

pub fn hkdf_expand(
    pseudorandom_key: &[u8],
    info: &[u8],
    output_length: usize,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let prk = exact_array::<32>("HKDF pseudorandom key", pseudorandom_key)?;
    let hkdf =
        Hkdf::<Sha3_256>::from_prk(&prk).map_err(|_| CryptoError::InvalidEncoding("HKDF PRK"))?;
    let mut output = Zeroizing::new(vec![0_u8; output_length]);
    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::OutputTooLong)?;
    Ok(output)
}
