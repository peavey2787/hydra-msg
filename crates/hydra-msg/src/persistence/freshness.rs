use crate::{Hydra, HydraMsgError, HydraResult};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

const STATE_FRESHNESS_DOMAIN: &[u8] = b"HYDRA-MSG/state-freshness";
const STATE_FRESHNESS_ANCHOR_BYTES: usize = 40;

/// Authenticated monotonic witness for externally detecting rollback of a
/// valid encrypted HYDRA state snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HydraStateFreshnessAnchor([u8; STATE_FRESHNESS_ANCHOR_BYTES]);

impl HydraStateFreshnessAnchor {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; STATE_FRESHNESS_ANCHOR_BYTES] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> [u8; STATE_FRESHNESS_ANCHOR_BYTES] {
        self.0
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> HydraResult<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != STATE_FRESHNESS_ANCHOR_BYTES {
            return Err(HydraMsgError::InvalidEncoding(
                "state freshness anchor size",
            ));
        }
        let mut out = [0_u8; STATE_FRESHNESS_ANCHOR_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("fixed generation bytes"))
    }
}

impl Hydra {
    #[must_use]
    pub fn state_freshness_anchor(&self) -> HydraStateFreshnessAnchor {
        let generation = self.state_generation;
        let tag = freshness_tag(self, generation);
        let mut bytes = [0_u8; STATE_FRESHNESS_ANCHOR_BYTES];
        bytes[..8].copy_from_slice(&generation.to_be_bytes());
        bytes[8..].copy_from_slice(&tag);
        HydraStateFreshnessAnchor(bytes)
    }

    pub fn verify_state_freshness_anchor(
        &mut self,
        anchor: HydraStateFreshnessAnchor,
    ) -> HydraResult<()> {
        let generation = anchor.generation();
        let expected = freshness_tag(self, generation);
        if !constant_time_eq(&anchor.as_bytes()[8..], &expected) {
            return Err(HydraMsgError::InvalidEncoding(
                "state freshness anchor authenticator",
            ));
        }
        if generation > self.state_generation {
            self.burn_all_sessions();
            return Err(HydraMsgError::StateRollbackDetected);
        }
        Ok(())
    }
}

fn freshness_tag(hydra: &Hydra, generation: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(STATE_FRESHNESS_DOMAIN.len() + 8);
    input.extend_from_slice(STATE_FRESHNESS_DOMAIN);
    input.extend_from_slice(&generation.to_be_bytes());
    RustCryptoBackend::hmac_sha3_256(&hydra.state_key, &input)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}
