use super::{
    governance::encode_mode_policy,
    primitives::{lp, u64_be},
};
use crate::{GroupError, GroupMode, GroupResult, MemberId, ModePolicy};
use hydra_core::{
    types::{Epoch, GroupId, IdentityFingerprint, Secret32},
    SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

pub fn member_id(
    group_id: GroupId,
    device_identity_fingerprint: IdentityFingerprint,
    joined_epoch: Epoch,
) -> MemberId {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/member-id");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&group_id.0);
    input.extend_from_slice(&device_identity_fingerprint.0);
    input.extend_from_slice(&u64_be(joined_epoch.0));
    MemberId(RustCryptoBackend::sha3_256(&input))
}

pub fn roster_hash(canonical_roster: &[u8]) -> GroupResult<[u8; 64]> {
    hash512_lp(b"HYDRA-MSG/v1/group/roster-hash", canonical_roster)
}

pub fn governance_policy_hash(canonical_governance_policy: &[u8]) -> GroupResult<[u8; 64]> {
    hash512_lp(
        b"HYDRA-MSG/v1/group/policy-hash",
        canonical_governance_policy,
    )
}

pub fn mode_policy_hash(mode_policy: ModePolicy) -> GroupResult<[u8; 64]> {
    hash512_lp(
        b"HYDRA-MSG/v1/group/mode-policy-hash",
        &encode_mode_policy(mode_policy),
    )
}

pub fn change_payload_hash(change_payload: &[u8]) -> GroupResult<[u8; 64]> {
    hash512_lp(b"HYDRA-MSG/v1/group/change-hash", change_payload)
}

pub fn direct_wrap_key_schedule_commitment(
    group_id: GroupId,
    new_group_mode: GroupMode,
    new_epoch: Epoch,
    commit_nonce: [u8; 32],
    epoch_secret: &Secret32,
) -> [u8; 64] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/epoch-secret-commitment");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&group_id.0);
    input.push(new_group_mode as u8);
    input.extend_from_slice(&u64_be(new_epoch.0));
    input.extend_from_slice(&commit_nonce);
    input.extend_from_slice(epoch_secret.expose_for_backend());
    RustCryptoBackend::sha3_512(&input)
}

pub fn treekem_key_schedule_commitment(
    group_id: GroupId,
    new_group_mode: GroupMode,
    new_epoch: Epoch,
    new_tree_hash: [u8; 64],
    update_path_hash: [u8; 64],
) -> [u8; 64] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/tree/commitment");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&group_id.0);
    input.push(new_group_mode as u8);
    input.extend_from_slice(&u64_be(new_epoch.0));
    input.extend_from_slice(&new_tree_hash);
    input.extend_from_slice(&update_path_hash);
    RustCryptoBackend::sha3_512(&input)
}

pub fn commit_sig_digest(commit_core: &[u8]) -> GroupResult<[u8; 64]> {
    hash512_lp(b"HYDRA-MSG/v1/group/commit-signature", commit_core)
}

pub fn commit_hash(commit_core: &[u8]) -> GroupResult<[u8; 64]> {
    hash512_lp(b"HYDRA-MSG/v1/group/commit-hash", commit_core)
}

#[must_use]
pub fn commit_confirmation_tag(
    group_id: GroupId,
    commit_hash: [u8; 64],
    key_schedule_commitment: [u8; 64],
) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/group/commit-confirmation");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&group_id.0);
    input.extend_from_slice(&commit_hash);
    input.extend_from_slice(&key_schedule_commitment);
    RustCryptoBackend::sha3_256(&input)
}

pub fn verify_commit_confirmation_tag(
    group_id: GroupId,
    commit_hash: [u8; 64],
    key_schedule_commitment: [u8; 64],
    candidate: &[u8; 32],
) -> GroupResult<()> {
    if &commit_confirmation_tag(group_id, commit_hash, key_schedule_commitment) == candidate {
        Ok(())
    } else {
        Err(GroupError::InvalidCommitCore)
    }
}

fn hash512_lp(label: &[u8], value: &[u8]) -> GroupResult<[u8; 64]> {
    let mut input = Vec::new();
    input.extend_from_slice(label);
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(&lp(value)?);
    Ok(RustCryptoBackend::sha3_512(&input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::{
            governance::encode_governance_policy,
            roster::encode_roster,
            test_support::{entry, group_id, sorted_governance},
        },
        GroupMode, ModePolicy,
    };
    use hydra_core::types::{Epoch, Secret32};

    #[test]
    fn hash_helpers_are_domain_separated_and_length_prefixed() {
        let roster = encode_roster(GroupMode::Interactive, &[entry(1, 1)]).unwrap();
        let roster_hash_a = roster_hash(&roster).unwrap();
        let mut changed = roster.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_ne!(roster_hash_a, roster_hash(&changed).unwrap());

        let governance = encode_governance_policy(&sorted_governance(1, 1)).unwrap();
        assert_ne!(roster_hash_a, governance_policy_hash(&governance).unwrap());
        assert_ne!(change_payload_hash(&roster).unwrap(), roster_hash_a);
        assert_ne!(
            mode_policy_hash(ModePolicy::default()).unwrap(),
            roster_hash_a
        );
    }

    #[test]
    fn key_schedule_commitments_are_mechanism_specific() {
        let group_id = group_id();
        let direct = direct_wrap_key_schedule_commitment(
            group_id,
            GroupMode::Lite,
            Epoch(7),
            [0x44; 32],
            &Secret32::new([0x55; 32]),
        );
        let tree = treekem_key_schedule_commitment(
            group_id,
            GroupMode::Interactive,
            Epoch(7),
            [0x66; 64],
            [0x77; 64],
        );
        assert_ne!(direct, tree);
        assert_ne!(
            direct,
            direct_wrap_key_schedule_commitment(
                group_id,
                GroupMode::Lite,
                Epoch(8),
                [0x44; 32],
                &Secret32::new([0x55; 32]),
            )
        );
    }
}
