use hydra_core::{types::Secret32, AEAD_NONCE_SIZE, ML_KEM_768_CT_SIZE, SUITE_ID};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};
use ml_kem::{ml_kem_768::EncapsulationKey, B32};

use crate::{lp, u32_be, u64_be, GroupError, GroupResult, PrivatePath, PublicNodeKey};

use super::{PathCiphertext, TreeKemWrapContext, WRAPPED_PATH_SECRET_SIZE};

const LABEL_WRAP_SALT: &[u8] = b"HYDRA-MSG/v1/group/tree/wrap-salt";
const LABEL_WRAP_KEY: &[u8] = b"HYDRA-MSG/v1/group/tree/wrap-key";
const LABEL_WRAP_ENTROPY: &[u8] = b"HYDRA-MSG/v1/group/tree/wrap-entropy";

pub fn wrap_context(
    context: &TreeKemWrapContext,
    parent_node_index: u32,
    target_node_index: u32,
) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&context.group_id.0);
    encoded.push(context.mode as u8);
    encoded.extend_from_slice(&u64_be(context.new_epoch.0));
    encoded.extend_from_slice(&u64_be(context.new_state_version.0));
    encoded.extend_from_slice(&context.commit_nonce);
    encoded.extend_from_slice(&u32_be(parent_node_index));
    encoded.extend_from_slice(&u32_be(target_node_index));
    encoded.extend_from_slice(&context.tree_hash);
    Ok(encoded)
}

pub(super) fn wrap_path_secret(
    context: &TreeKemWrapContext,
    parent_node_index: u32,
    target_node_index: u32,
    node_key: &PublicNodeKey,
    path_secret: &Secret32,
) -> GroupResult<PathCiphertext> {
    let wrap_context = wrap_context(context, parent_node_index, target_node_index)?;
    let (kem_ciphertext, mut kem_shared_secret) =
        deterministic_encapsulate(node_key, &wrap_context)?;
    let wrap_key = derive_wrap_key(&wrap_context, &kem_shared_secret)?;
    kem_shared_secret.fill(0);

    let mut aad = Vec::with_capacity(wrap_context.len() + kem_ciphertext.len());
    aad.extend_from_slice(&wrap_context);
    aad.extend_from_slice(&kem_ciphertext);
    let sealed = RustCryptoBackend::aead_seal(
        &SecretBytes::from_array(wrap_key),
        &[0_u8; AEAD_NONCE_SIZE],
        &aad,
        path_secret.expose_for_backend(),
    )
    .map_err(|_| GroupError::InvalidTreePath)?;
    let wrapped_path_secret: [u8; WRAPPED_PATH_SECRET_SIZE] = sealed
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)?;
    Ok(PathCiphertext {
        parent_node_index,
        target_node_index,
        kem_ciphertext,
        wrapped_path_secret,
    })
}

fn deterministic_encapsulate(
    node_key: &PublicNodeKey,
    wrap_context: &[u8],
) -> GroupResult<([u8; ML_KEM_768_CT_SIZE], [u8; 32])> {
    let mut encoded_key = ml_kem::kem::Key::<EncapsulationKey>::default();
    encoded_key.copy_from_slice(&node_key.0);
    let encapsulation_key =
        EncapsulationKey::new(&encoded_key).map_err(|_| GroupError::InvalidTreeResolution)?;
    let wrap_entropy = derive_wrap_entropy(wrap_context)?;
    let mut entropy: B32 = wrap_entropy.into();
    let (ciphertext, mut shared_secret) = encapsulation_key.encapsulate_deterministic(&entropy);
    entropy.as_mut_slice().fill(0);
    let mut encoded_ciphertext = [0_u8; ML_KEM_768_CT_SIZE];
    encoded_ciphertext.copy_from_slice(ciphertext.as_ref());
    let mut encoded_shared_secret = [0_u8; 32];
    encoded_shared_secret.copy_from_slice(shared_secret.as_ref());
    shared_secret.as_mut_slice().fill(0);
    Ok((encoded_ciphertext, encoded_shared_secret))
}

fn derive_wrap_entropy(wrap_context: &[u8]) -> GroupResult<[u8; 32]> {
    let mut info = Vec::new();
    info.extend_from_slice(&lp(LABEL_WRAP_ENTROPY)?);
    info.extend_from_slice(&lp(wrap_context)?);
    let output = RustCryptoBackend::hkdf_expand(&[0_u8; 32], &info, 32)
        .map_err(|_| GroupError::InvalidTreePath)?;
    output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)
}

fn derive_wrap_key(wrap_context: &[u8], kem_shared_secret: &[u8]) -> GroupResult<[u8; 32]> {
    let mut salt_input = Vec::new();
    salt_input.extend_from_slice(LABEL_WRAP_SALT);
    salt_input.extend_from_slice(&SUITE_ID);
    salt_input.extend_from_slice(&lp(wrap_context)?);
    let salt = RustCryptoBackend::sha3_512(&salt_input);
    let wrap_prk = RustCryptoBackend::hkdf_extract(&salt, kem_shared_secret);
    let mut info = Vec::new();
    info.extend_from_slice(&lp(LABEL_WRAP_KEY)?);
    info.extend_from_slice(&lp(wrap_context)?);
    let output = RustCryptoBackend::hkdf_expand(wrap_prk.expose_secret(), &info, 32)
        .map_err(|_| GroupError::InvalidTreePath)?;
    output
        .as_slice()
        .try_into()
        .map_err(|_| GroupError::InvalidTreePath)
}

pub(super) fn private_path_secret(
    private_path: &PrivatePath,
    node_index: u32,
) -> GroupResult<&Secret32> {
    private_path
        .path
        .iter()
        .find(|secret| secret.node_index == node_index)
        .map(|secret| &secret.path_secret)
        .ok_or(GroupError::InvalidTreePath)
}
