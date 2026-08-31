use super::{AcceptedInitKey, HandshakePurpose};
use crate::{
    codec::identity_fingerprint, identity::IdentityRecord, limits::MAX_PENDING_HANDSHAKE_AGE_SECS,
    ContactId, Hydra, HydraMsgError, HydraResult,
};
use hydra_crypto::{MlDsaKeyPair, MlDsaSigningKey};
use std::{cmp::Ordering, time::Duration};

pub(super) fn identity_signing_key(record: &IdentityRecord) -> HydraResult<MlDsaSigningKey> {
    let seed = record
        .seed
        .ok_or(HydraMsgError::InvalidInput("active identity is locked"))?;
    Ok(MlDsaKeyPair::from_seed(seed)?.signing_key)
}

pub(super) fn expire_handshakes(hydra: &mut Hydra) {
    let max_age = Duration::from_secs(MAX_PENDING_HANDSHAKE_AGE_SECS);
    hydra
        .pending_offers
        .retain(|_, pending| pending.created_at.elapsed() <= max_age);
    hydra
        .accepted_inits
        .retain(|_, accepted| accepted.created_at.elapsed() <= max_age);
}

pub(super) fn pending_retry(
    hydra: &Hydra,
    contact_id: ContactId,
    local_identity_id: crate::IdentityId,
    purpose: HandshakePurpose,
) -> Option<Vec<u8>> {
    hydra
        .pending_offers
        .values()
        .find(|pending| {
            pending.contact_id == contact_id
                && pending.local_identity_id == local_identity_id
                && pending.purpose == purpose
        })
        .map(|pending| pending.offer_bytes.clone())
}

pub(super) fn reject_other_pending_attempt(
    hydra: &Hydra,
    contact_id: ContactId,
    local_identity_id: crate::IdentityId,
    purpose: HandshakePurpose,
) -> HydraResult<()> {
    if hydra.pending_offers.values().any(|pending| {
        pending.contact_id == contact_id
            && pending.purpose == purpose
            && pending.local_identity_id != local_identity_id
    }) {
        return Err(HydraMsgError::InvalidInput(
            "competing handshake already pending for another local identity",
        ));
    }
    Ok(())
}

pub(super) fn prepare_local_initiator_attempt(
    hydra: &Hydra,
    contact_id: ContactId,
    local_public_key: &[u8; hydra_core::ML_DSA_65_VK_SIZE],
    peer_public_key: &[u8; hydra_core::ML_DSA_65_VK_SIZE],
    purpose: HandshakePurpose,
) -> HydraResult<bool> {
    let has_inbound = hydra.accepted_inits.values().any(|accepted| {
        accepted.contact_id == contact_id
            && accepted.purpose == purpose
            && accepted.candidate.is_some()
    });
    if !has_inbound {
        return Ok(false);
    }
    match identity_fingerprint(local_public_key).cmp(&identity_fingerprint(peer_public_key)) {
        Ordering::Less => Ok(true),
        Ordering::Greater => Err(HydraMsgError::InvalidInput(
            "competing responder handshake takes precedence",
        )),
        Ordering::Equal => Err(HydraMsgError::InvalidInput(
            "competing handshake identity collision",
        )),
    }
}

pub(super) fn supersede_inbound_candidates(
    hydra: &mut Hydra,
    contact_id: ContactId,
    purpose: HandshakePurpose,
) {
    for accepted in hydra.accepted_inits.values_mut() {
        if accepted.contact_id == contact_id && accepted.purpose == purpose {
            accepted.candidate = None;
        }
    }
}

pub(super) fn prepare_inbound_responder_attempt(
    hydra: &Hydra,
    contact_id: ContactId,
    local_public_key: &[u8; hydra_core::ML_DSA_65_VK_SIZE],
    initiator_fingerprint: [u8; 32],
    purpose: HandshakePurpose,
) -> HydraResult<bool> {
    let local_fingerprint = identity_fingerprint(local_public_key);
    let has_outbound = hydra
        .pending_offers
        .values()
        .any(|pending| pending.contact_id == contact_id && pending.purpose == purpose);
    let supersede_outbound = if has_outbound {
        match local_fingerprint.cmp(&initiator_fingerprint) {
            Ordering::Less => {
                return Err(HydraMsgError::InvalidInput(
                    "competing local initiator handshake takes precedence",
                ));
            }
            Ordering::Greater => true,
            Ordering::Equal => {
                return Err(HydraMsgError::InvalidInput(
                    "competing handshake identity collision",
                ));
            }
        }
    } else {
        false
    };
    if hydra.accepted_inits.values().any(|accepted| {
        accepted.contact_id == contact_id
            && accepted.purpose == purpose
            && accepted.candidate.is_some()
    }) {
        return Err(HydraMsgError::InvalidInput(
            "competing INIT already has provisional responder state",
        ));
    }
    Ok(supersede_outbound)
}

pub(super) fn supersede_outbound_attempts(
    hydra: &mut Hydra,
    contact_id: ContactId,
    purpose: HandshakePurpose,
) {
    hydra
        .pending_offers
        .retain(|_, pending| pending.contact_id != contact_id || pending.purpose != purpose);
}

pub(super) fn retire_competing_handshakes(
    hydra: &mut Hydra,
    contact_id: ContactId,
    keep_accepted: Option<AcceptedInitKey>,
) {
    hydra
        .pending_offers
        .retain(|_, pending| pending.contact_id != contact_id);
    for (key, accepted) in &mut hydra.accepted_inits {
        if accepted.contact_id == contact_id && Some(*key) != keep_accepted {
            accepted.candidate = None;
        }
    }
}

#[cfg(test)]
mod tests;
