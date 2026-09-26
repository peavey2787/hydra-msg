use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

use crate::{SessionError, SessionResult};

pub struct InitialSessionSecrets {
    pub session_id: [u8; 32],
    pub chain_i2r: SecretBytes<32>,
    pub chain_r2i: SecretBytes<32>,
    pub refresh_root: SecretBytes<32>,
}

fn info(label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 + label.len() + context.len());
    output.extend_from_slice(&(label.len() as u32).to_be_bytes());
    output.extend_from_slice(label);
    output.extend_from_slice(&(context.len() as u32).to_be_bytes());
    output.extend_from_slice(context);
    output
}

pub(crate) fn expand32(
    key: &SecretBytes<32>,
    label: &[u8],
    context: &[u8],
) -> SessionResult<SecretBytes<32>> {
    let output = RustCryptoBackend::hkdf_expand(key.expose_secret(), &info(label, context), 32)
        .map_err(|_| SessionError::InvalidState)?;
    let bytes: [u8; 32] = output
        .as_slice()
        .try_into()
        .map_err(|_| SessionError::InvalidState)?;
    Ok(SecretBytes::from_array(bytes))
}

pub fn derive_initial_secrets(
    handshake_secret: &SecretBytes<32>,
    transcript_hash: &[u8; 64],
) -> SessionResult<InitialSessionSecrets> {
    let expand = |label: &[u8]| expand32(handshake_secret, label, transcript_hash);
    let sid = expand(b"HYDRA-MSG/v1/session-id")?;
    let session_id = *sid.expose_secret();
    let chain_i2r = expand(b"HYDRA-MSG/v1/init-chain/i2r")?;
    let chain_r2i = expand(b"HYDRA-MSG/v1/init-chain/r2i")?;
    let refresh_root = expand(b"HYDRA-MSG/v1/refresh-root")?;
    Ok(InitialSessionSecrets {
        session_id,
        chain_i2r,
        chain_r2i,
        refresh_root,
    })
}
