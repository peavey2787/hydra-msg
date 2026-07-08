use hydra_core::{LABEL_CHAIN_STEP, LABEL_MESSAGE_KEY};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

use crate::{key_derivation::expand32, SessionResult};

const LABEL_AEAD_KEY: &[u8] = b"HYDRA-MSG/v1/aead-key";
const LABEL_ROUTE_TAG: &[u8] = b"HYDRA-MSG/v1/route-tag";

pub struct DirectionChain {
    key: SecretBytes<32>,
    next_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectionChainSnapshot {
    pub key: [u8; 32],
    pub next_index: u64,
}

impl DirectionChain {
    #[must_use]
    pub const fn new(key: SecretBytes<32>) -> Self {
        Self { key, next_index: 0 }
    }

    #[must_use]
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    pub(crate) fn key(&self) -> &SecretBytes<32> {
        &self.key
    }

    pub(crate) fn install(&mut self, key: SecretBytes<32>, next_index: u64) {
        self.key = key;
        self.next_index = next_index;
    }

    #[must_use]
    pub fn export_snapshot(&self) -> DirectionChainSnapshot {
        DirectionChainSnapshot {
            key: *self.key.expose_secret(),
            next_index: self.next_index,
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: DirectionChainSnapshot) -> Self {
        Self {
            key: SecretBytes::from_array(snapshot.key),
            next_index: snapshot.next_index,
        }
    }
}

pub struct RatchetStep {
    pub message_key: SecretBytes<32>,
    pub next_chain_key: SecretBytes<32>,
    pub aead_key: SecretBytes<32>,
    pub route_tag: [u8; 16],
}

pub fn derive_aead_key(
    message_key: &SecretBytes<32>,
    session_id: &[u8; 32],
    index: u64,
) -> SessionResult<SecretBytes<32>> {
    let mut context = [0_u8; 40];
    context[..32].copy_from_slice(session_id);
    context[32..].copy_from_slice(&index.to_be_bytes());
    expand32(message_key, LABEL_AEAD_KEY, &context)
}

#[must_use]
pub fn derive_route_tag(
    message_key: &SecretBytes<32>,
    session_id: &[u8; 32],
    index: u64,
) -> [u8; 16] {
    let mut input = Vec::with_capacity(LABEL_ROUTE_TAG.len() + 40);
    input.extend_from_slice(LABEL_ROUTE_TAG);
    input.extend_from_slice(session_id);
    input.extend_from_slice(&index.to_be_bytes());
    let full = RustCryptoBackend::hmac_sha3_256(message_key, &input);
    full[..16].try_into().expect("route tag has fixed length")
}

pub fn derive_step(
    chain_key: &SecretBytes<32>,
    session_id: &[u8; 32],
    index: u64,
) -> SessionResult<RatchetStep> {
    let mut context = [0_u8; 40];
    context[..32].copy_from_slice(session_id);
    context[32..].copy_from_slice(&index.to_be_bytes());

    let message_key = expand32(chain_key, LABEL_MESSAGE_KEY, &context)?;
    let next_chain_key = expand32(chain_key, LABEL_CHAIN_STEP, &context)?;
    let aead_key = derive_aead_key(&message_key, session_id, index)?;
    let route_tag = derive_route_tag(&message_key, session_id, index);
    Ok(RatchetStep {
        message_key,
        next_chain_key,
        aead_key,
        route_tag,
    })
}

#[must_use]
pub(crate) fn constant_time_tag_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
