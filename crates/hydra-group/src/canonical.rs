use hydra_core::{
    types::{Epoch, GroupId, IdentityFingerprint, Secret32},
    MAX_COMMIT_SIGNATURES, MAX_GOVERNANCE_SIGNERS, ML_DSA_65_SIG_SIZE, SUITE_ID,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend};

use crate::{
    CommitKind, GovernancePolicy, GroupError, GroupMode, GroupResult, GroupRole, MemberId,
    MemberStatus, MembershipMechanism, ModePolicy, RosterEntry, StateVersion,
};

pub const ROSTER_ENTRY_SIZE: usize = 86;
pub const MODE_POLICY_SIZE: usize = 12;
pub const COMMIT_CORE_SIZE: usize = 676;

#[must_use]
pub fn u16_be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

#[must_use]
pub fn u32_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

#[must_use]
pub fn u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn checked_u16_be(value: usize) -> GroupResult<[u8; 2]> {
    let value = u16::try_from(value).map_err(|_| GroupError::InvalidLength {
        field: "u16",
        actual: value,
        maximum: u16::MAX as usize,
    })?;
    Ok(value.to_be_bytes())
}

pub fn checked_u32_be(value: usize) -> GroupResult<[u8; 4]> {
    let value = u32::try_from(value).map_err(|_| GroupError::InvalidLength {
        field: "u32",
        actual: value,
        maximum: u32::MAX as usize,
    })?;
    Ok(value.to_be_bytes())
}

pub fn lp(value: &[u8]) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::with_capacity(4 + value.len());
    encoded.extend_from_slice(&checked_u32_be(value.len())?);
    encoded.extend_from_slice(value);
    Ok(encoded)
}

#[must_use]
pub fn encode_mode_policy(policy: ModePolicy) -> [u8; MODE_POLICY_SIZE] {
    policy.bytes
}

pub fn encode_roster_entry(entry: &RosterEntry) -> [u8; ROSTER_ENTRY_SIZE] {
    let mut encoded = [0_u8; ROSTER_ENTRY_SIZE];
    encoded[0..32].copy_from_slice(&entry.member_id.0);
    encoded[32..64].copy_from_slice(&entry.device_identity_fingerprint.0);
    encoded[64] = entry.role as u8;
    encoded[65] = entry.status as u8;
    encoded[66..70].copy_from_slice(&u32_be(entry.tree_leaf_slot));
    encoded[70..78].copy_from_slice(&u64_be(entry.joined_epoch.0));
    encoded[78..86].copy_from_slice(&u64_be(entry.removed_epoch.0));
    encoded
}

pub fn encode_roster(mode: GroupMode, roster: &[RosterEntry]) -> GroupResult<Vec<u8>> {
    validate_roster_for_canonical_encoding(mode, roster)?;
    let mut ordered = roster.to_vec();
    ordered.sort_by_key(|entry| entry.member_id.0);

    let mut encoded = Vec::with_capacity(2 + ordered.len() * ROSTER_ENTRY_SIZE);
    encoded.extend_from_slice(&checked_u16_be(ordered.len())?);
    for entry in &ordered {
        encoded.extend_from_slice(&encode_roster_entry(entry));
    }
    Ok(encoded)
}

pub fn validate_roster_for_canonical_encoding(
    mode: GroupMode,
    roster: &[RosterEntry],
) -> GroupResult<()> {
    if roster.is_empty() || roster.len() > mode.max_roster_entries() {
        return Err(GroupError::InvalidRoster);
    }

    let mut member_ids = roster
        .iter()
        .map(|entry| entry.member_id.0)
        .collect::<Vec<_>>();
    member_ids.sort_unstable();
    if member_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GroupError::InvalidRoster);
    }

    let mut active_fingerprints = roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
        .map(|entry| entry.device_identity_fingerprint.0)
        .collect::<Vec<_>>();
    active_fingerprints.sort_unstable();
    if active_fingerprints
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(GroupError::InvalidRoster);
    }

    Ok(())
}

pub fn encode_governance_policy(policy: &GovernancePolicy) -> GroupResult<Vec<u8>> {
    validate_governance_policy(policy)?;
    let mut encoded = Vec::with_capacity(4 + policy.authorized_signers.len() * 32);
    encoded.push(policy.policy_version);
    encoded.push(policy.threshold);
    encoded.push(
        u8::try_from(policy.authorized_signers.len())
            .map_err(|_| GroupError::InvalidGovernancePolicy)?,
    );
    encoded.push(0);
    for signer in &policy.authorized_signers {
        encoded.extend_from_slice(&signer.0);
    }
    Ok(encoded)
}

pub fn validate_governance_policy(policy: &GovernancePolicy) -> GroupResult<()> {
    let count = policy.authorized_signers.len();
    if policy.policy_version != 1
        || policy.threshold == 0
        || usize::from(policy.threshold) > count
        || count == 0
        || count > MAX_GOVERNANCE_SIGNERS
        || policy.threshold > MAX_GOVERNANCE_SIGNERS as u8
    {
        return Err(GroupError::InvalidGovernancePolicy);
    }
    if !is_strictly_ordered_member_ids(&policy.authorized_signers) {
        return Err(GroupError::InvalidGovernancePolicy);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitSignature {
    pub signer: MemberId,
    pub signature: [u8; ML_DSA_65_SIG_SIZE],
}

pub fn encode_signature_set(signatures: &[CommitSignature]) -> GroupResult<Vec<u8>> {
    validate_signature_set(signatures)?;
    let mut encoded = Vec::with_capacity(1 + signatures.len() * (32 + ML_DSA_65_SIG_SIZE));
    encoded.push(u8::try_from(signatures.len()).map_err(|_| GroupError::InvalidSignatureSet)?);
    for signature in signatures {
        encoded.extend_from_slice(&signature.signer.0);
        encoded.extend_from_slice(&signature.signature);
    }
    Ok(encoded)
}

pub fn validate_signature_set(signatures: &[CommitSignature]) -> GroupResult<()> {
    if signatures.is_empty() || signatures.len() > MAX_COMMIT_SIGNATURES {
        return Err(GroupError::InvalidSignatureSet);
    }
    let signers = signatures
        .iter()
        .map(|signature| signature.signer)
        .collect::<Vec<_>>();
    if !is_strictly_ordered_member_ids(&signers) {
        return Err(GroupError::InvalidSignatureSet);
    }
    Ok(())
}

pub enum ChangePayload<'a> {
    Create {
        new_governance_policy: &'a GovernancePolicy,
        new_mode_policy: ModePolicy,
    },
    Join {
        new_entry: &'a RosterEntry,
    },
    Leave {
        member_id: MemberId,
    },
    RemoveOrRevoke {
        member_id: MemberId,
        reason_code: u16,
    },
    GovernanceChange {
        new_governance_policy: &'a GovernancePolicy,
    },
    IdentityRotate {
        old_member_id: MemberId,
        new_entry: &'a RosterEntry,
        rotation_digest: [u8; 64],
    },
    RoleChange {
        member_id: MemberId,
        old_role: GroupRole,
        new_role: GroupRole,
    },
    ModeChange {
        old_mode: GroupMode,
        new_mode: GroupMode,
        new_mode_policy: ModePolicy,
    },
    TreeSelfUpdate {
        committer_member_id: MemberId,
    },
}

impl ChangePayload<'_> {
    #[must_use]
    pub const fn kind(&self) -> CommitKind {
        match self {
            Self::Create { .. } => CommitKind::Create,
            Self::Join { .. } => CommitKind::Join,
            Self::Leave { .. } => CommitKind::Leave,
            Self::RemoveOrRevoke { .. } => CommitKind::RemoveOrRevoke,
            Self::GovernanceChange { .. } => CommitKind::GovernanceChange,
            Self::IdentityRotate { .. } => CommitKind::IdentityRotate,
            Self::RoleChange { .. } => CommitKind::RoleChange,
            Self::ModeChange { .. } => CommitKind::ModeChange,
            Self::TreeSelfUpdate { .. } => CommitKind::TreeSelfUpdate,
        }
    }
}

pub fn encode_change_payload(payload: &ChangePayload<'_>) -> GroupResult<Vec<u8>> {
    let mut encoded = Vec::new();
    match payload {
        ChangePayload::Create {
            new_governance_policy,
            new_mode_policy,
        } => {
            encoded.extend_from_slice(&lp(&encode_governance_policy(new_governance_policy)?)?);
            encoded.extend_from_slice(&lp(&encode_mode_policy(*new_mode_policy))?);
        }
        ChangePayload::Join { new_entry } => {
            encoded.extend_from_slice(&encode_roster_entry(new_entry));
        }
        ChangePayload::Leave { member_id } => {
            encoded.extend_from_slice(&member_id.0);
        }
        ChangePayload::RemoveOrRevoke {
            member_id,
            reason_code,
        } => {
            encoded.extend_from_slice(&member_id.0);
            encoded.extend_from_slice(&u16_be(*reason_code));
        }
        ChangePayload::GovernanceChange {
            new_governance_policy,
        } => {
            encoded.extend_from_slice(&lp(&encode_governance_policy(new_governance_policy)?)?);
        }
        ChangePayload::IdentityRotate {
            old_member_id,
            new_entry,
            rotation_digest,
        } => {
            encoded.extend_from_slice(&old_member_id.0);
            encoded.extend_from_slice(&encode_roster_entry(new_entry));
            encoded.extend_from_slice(rotation_digest);
        }
        ChangePayload::RoleChange {
            member_id,
            old_role,
            new_role,
        } => {
            encoded.extend_from_slice(&member_id.0);
            encoded.push(*old_role as u8);
            encoded.push(*new_role as u8);
        }
        ChangePayload::ModeChange {
            old_mode,
            new_mode,
            new_mode_policy,
        } => {
            encoded.push(*old_mode as u8);
            encoded.push(*new_mode as u8);
            encoded.extend_from_slice(&lp(&encode_mode_policy(*new_mode_policy))?);
        }
        ChangePayload::TreeSelfUpdate {
            committer_member_id,
        } => {
            encoded.extend_from_slice(&committer_member_id.0);
        }
    }
    Ok(encoded)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitCore {
    pub commit_kind: CommitKind,
    pub group_id: GroupId,
    pub old_group_mode: Option<GroupMode>,
    pub new_group_mode: GroupMode,
    pub new_membership_mechanism: MembershipMechanism,
    pub old_epoch: Epoch,
    pub new_epoch: Epoch,
    pub old_state_version: StateVersion,
    pub new_state_version: StateVersion,
    pub parent_commit_hash: [u8; 64],
    pub old_roster_hash: [u8; 64],
    pub new_roster_hash: [u8; 64],
    pub old_tree_hash: [u8; 64],
    pub new_tree_hash: [u8; 64],
    pub commit_nonce: [u8; 32],
    pub change_payload_hash: [u8; 64],
    pub key_schedule_commitment: [u8; 64],
    pub governance_policy_hash: [u8; 64],
    pub mode_policy_hash: [u8; 64],
}

pub fn encode_commit_core(core: &CommitCore) -> GroupResult<Vec<u8>> {
    if core.new_membership_mechanism != core.new_group_mode.required_mechanism() {
        return Err(GroupError::InvalidModeMechanism {
            mode: core.new_group_mode,
            mechanism: core.new_membership_mechanism,
        });
    }
    if core.old_group_mode.is_none() && core.commit_kind != CommitKind::Create {
        return Err(GroupError::InvalidCommitCore);
    }

    let mut encoded = Vec::with_capacity(COMMIT_CORE_SIZE);
    encoded.push(core.commit_kind as u8);
    encoded.extend_from_slice(&core.group_id.0);
    encoded.push(core.old_group_mode.map_or(0, |mode| mode as u8));
    encoded.push(core.new_group_mode as u8);
    encoded.push(core.new_membership_mechanism as u8);
    encoded.extend_from_slice(&u64_be(core.old_epoch.0));
    encoded.extend_from_slice(&u64_be(core.new_epoch.0));
    encoded.extend_from_slice(&u64_be(core.old_state_version.0));
    encoded.extend_from_slice(&u64_be(core.new_state_version.0));
    encoded.extend_from_slice(&core.parent_commit_hash);
    encoded.extend_from_slice(&core.old_roster_hash);
    encoded.extend_from_slice(&core.new_roster_hash);
    encoded.extend_from_slice(&core.old_tree_hash);
    encoded.extend_from_slice(&core.new_tree_hash);
    encoded.extend_from_slice(&core.commit_nonce);
    encoded.extend_from_slice(&core.change_payload_hash);
    encoded.extend_from_slice(&core.key_schedule_commitment);
    encoded.extend_from_slice(&core.governance_policy_hash);
    encoded.extend_from_slice(&core.mode_policy_hash);
    debug_assert_eq!(encoded.len(), COMMIT_CORE_SIZE);
    Ok(encoded)
}

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

fn is_strictly_ordered_member_ids(ids: &[MemberId]) -> bool {
    ids.windows(2).all(|pair| pair[0].0 < pair[1].0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_id() -> GroupId {
        GroupId([0x42; 32])
    }

    fn member(value: u8) -> MemberId {
        MemberId([value; 32])
    }

    fn fingerprint(value: u8) -> IdentityFingerprint {
        IdentityFingerprint([value; 32])
    }

    fn entry(member_value: u8, fingerprint_value: u8) -> RosterEntry {
        RosterEntry {
            member_id: member(member_value),
            device_identity_fingerprint: fingerprint(fingerprint_value),
            role: GroupRole::Member,
            status: MemberStatus::Active,
            tree_leaf_slot: u32::from(member_value),
            joined_epoch: Epoch(1),
            removed_epoch: Epoch(0),
        }
    }

    fn sorted_governance(count: u8, threshold: u8) -> GovernancePolicy {
        GovernancePolicy {
            policy_version: 1,
            threshold,
            authorized_signers: (1..=count).map(member).collect(),
        }
    }

    fn commit_core() -> CommitCore {
        CommitCore {
            commit_kind: CommitKind::Join,
            group_id: group_id(),
            old_group_mode: Some(GroupMode::Interactive),
            new_group_mode: GroupMode::Interactive,
            new_membership_mechanism: MembershipMechanism::TreeKem,
            old_epoch: Epoch(1),
            new_epoch: Epoch(2),
            old_state_version: StateVersion(3),
            new_state_version: StateVersion(4),
            parent_commit_hash: [1; 64],
            old_roster_hash: [2; 64],
            new_roster_hash: [3; 64],
            old_tree_hash: [4; 64],
            new_tree_hash: [5; 64],
            commit_nonce: [6; 32],
            change_payload_hash: [7; 64],
            key_schedule_commitment: [8; 64],
            governance_policy_hash: [9; 64],
            mode_policy_hash: [10; 64],
        }
    }

    #[test]
    fn length_prefixed_and_integer_encoders_are_big_endian_and_checked() {
        assert_eq!(u16_be(0x0102), [0x01, 0x02]);
        assert_eq!(u32_be(0x0102_0304), [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            u64_be(0x0102_0304_0506_0708),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(lp(b"abc").unwrap(), b"\0\0\0\x03abc".to_vec());
        assert_eq!(checked_u16_be(u16::MAX as usize).unwrap(), [0xff, 0xff]);
        assert!(checked_u16_be(u16::MAX as usize + 1).is_err());
    }

    #[test]
    fn roster_entry_encoding_is_exactly_86_bytes() {
        let encoded = encode_roster_entry(&entry(1, 2));
        assert_eq!(encoded.len(), ROSTER_ENTRY_SIZE);
        assert_eq!(&encoded[0..32], &[1; 32]);
        assert_eq!(&encoded[32..64], &[2; 32]);
        assert_eq!(encoded[64], GroupRole::Member as u8);
        assert_eq!(encoded[65], MemberStatus::Active as u8);
        assert_eq!(&encoded[66..70], &1_u32.to_be_bytes());
        assert_eq!(&encoded[70..78], &1_u64.to_be_bytes());
        assert_eq!(&encoded[78..86], &0_u64.to_be_bytes());
    }

    #[test]
    fn canonical_roster_orders_by_member_id_and_rejects_duplicates() {
        let encoded = encode_roster(GroupMode::Interactive, &[entry(3, 3), entry(1, 1)]).unwrap();
        assert_eq!(&encoded[0..2], &2_u16.to_be_bytes());
        assert_eq!(&encoded[2..34], &[1; 32]);
        assert_eq!(
            &encoded[2 + ROSTER_ENTRY_SIZE..34 + ROSTER_ENTRY_SIZE],
            &[3; 32]
        );

        assert_eq!(
            encode_roster(GroupMode::Interactive, &[entry(1, 1), entry(1, 2)]),
            Err(GroupError::InvalidRoster)
        );
        assert_eq!(
            encode_roster(GroupMode::Interactive, &[entry(1, 7), entry(2, 7)]),
            Err(GroupError::InvalidRoster)
        );
    }

    #[test]
    fn roster_count_boundaries_are_explicit() {
        assert_eq!(
            encode_roster(GroupMode::Lite, &[]),
            Err(GroupError::InvalidRoster)
        );

        let one = vec![entry(1, 1)];
        assert!(encode_roster(GroupMode::Lite, &one).is_ok());

        let at_max = (0..hydra_core::MAX_LITE_MEMBERS)
            .map(|index| entry(index as u8 + 1, index as u8 + 1))
            .collect::<Vec<_>>();
        assert!(encode_roster(GroupMode::Lite, &at_max).is_ok());

        let too_many = (0..=hydra_core::MAX_LITE_MEMBERS)
            .map(|index| entry(index as u8 + 1, index as u8 + 1))
            .collect::<Vec<_>>();
        assert_eq!(
            encode_roster(GroupMode::Lite, &too_many),
            Err(GroupError::InvalidRoster)
        );
    }

    #[test]
    fn governance_policy_boundaries_are_enforced() {
        assert_eq!(
            encode_governance_policy(&GovernancePolicy {
                policy_version: 1,
                threshold: 1,
                authorized_signers: Vec::new(),
            }),
            Err(GroupError::InvalidGovernancePolicy)
        );
        assert_eq!(
            encode_governance_policy(&sorted_governance(1, 0)),
            Err(GroupError::InvalidGovernancePolicy)
        );
        assert!(encode_governance_policy(&sorted_governance(1, 1)).is_ok());
        assert!(encode_governance_policy(&sorted_governance(16, 16)).is_ok());
        assert_eq!(
            encode_governance_policy(&sorted_governance(16, 17)),
            Err(GroupError::InvalidGovernancePolicy)
        );
        assert_eq!(
            encode_governance_policy(&sorted_governance(17, 1)),
            Err(GroupError::InvalidGovernancePolicy)
        );

        let mut above_count = sorted_governance(3, 4);
        assert_eq!(
            encode_governance_policy(&above_count),
            Err(GroupError::InvalidGovernancePolicy)
        );
        above_count.threshold = 3;
        above_count.authorized_signers.reverse();
        assert_eq!(
            encode_governance_policy(&above_count),
            Err(GroupError::InvalidGovernancePolicy)
        );
        above_count.authorized_signers = vec![member(1), member(1)];
        above_count.threshold = 1;
        assert_eq!(
            encode_governance_policy(&above_count),
            Err(GroupError::InvalidGovernancePolicy)
        );
    }

    #[test]
    fn signature_set_count_and_order_boundaries_are_enforced() {
        assert_eq!(
            encode_signature_set(&[]),
            Err(GroupError::InvalidSignatureSet)
        );
        let one = vec![CommitSignature {
            signer: member(1),
            signature: [0x11; ML_DSA_65_SIG_SIZE],
        }];
        assert!(encode_signature_set(&one).is_ok());

        let seventeen = (1..=MAX_COMMIT_SIGNATURES)
            .map(|index| CommitSignature {
                signer: member(index as u8),
                signature: [index as u8; ML_DSA_65_SIG_SIZE],
            })
            .collect::<Vec<_>>();
        assert!(encode_signature_set(&seventeen).is_ok());

        let eighteen = (1..=MAX_COMMIT_SIGNATURES + 1)
            .map(|index| CommitSignature {
                signer: member(index as u8),
                signature: [index as u8; ML_DSA_65_SIG_SIZE],
            })
            .collect::<Vec<_>>();
        assert_eq!(
            encode_signature_set(&eighteen),
            Err(GroupError::InvalidSignatureSet)
        );

        let unsorted = vec![
            CommitSignature {
                signer: member(2),
                signature: [2; ML_DSA_65_SIG_SIZE],
            },
            CommitSignature {
                signer: member(1),
                signature: [1; ML_DSA_65_SIG_SIZE],
            },
        ];
        assert_eq!(
            encode_signature_set(&unsorted),
            Err(GroupError::InvalidSignatureSet)
        );
    }

    #[test]
    fn every_change_payload_kind_uses_the_normative_shape() {
        let governance = sorted_governance(1, 1);
        let mode_policy = ModePolicy { bytes: [0xa5; 12] };
        let new_entry = entry(4, 5);

        let create = encode_change_payload(&ChangePayload::Create {
            new_governance_policy: &governance,
            new_mode_policy: mode_policy,
        })
        .unwrap();
        assert!(create.starts_with(&u32_be(36)));
        assert_eq!(&create[40..44], &u32_be(12));

        assert_eq!(
            encode_change_payload(&ChangePayload::Join {
                new_entry: &new_entry
            })
            .unwrap()
            .len(),
            ROSTER_ENTRY_SIZE
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::Leave {
                member_id: member(1)
            })
            .unwrap()
            .len(),
            32
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::RemoveOrRevoke {
                member_id: member(1),
                reason_code: 7,
            })
            .unwrap()
            .len(),
            34
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::RoleChange {
                member_id: member(1),
                old_role: GroupRole::Member,
                new_role: GroupRole::Moderator,
            })
            .unwrap()
            .len(),
            34
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::ModeChange {
                old_mode: GroupMode::Interactive,
                new_mode: GroupMode::Lite,
                new_mode_policy: mode_policy,
            })
            .unwrap()
            .len(),
            18
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::TreeSelfUpdate {
                committer_member_id: member(1)
            })
            .unwrap()
            .len(),
            32
        );
        assert_eq!(
            encode_change_payload(&ChangePayload::IdentityRotate {
                old_member_id: member(1),
                new_entry: &new_entry,
                rotation_digest: [9; 64],
            })
            .unwrap()
            .len(),
            32 + ROSTER_ENTRY_SIZE + 64
        );
    }

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
    fn commit_core_encoding_and_hashes_are_exact_size_and_domain_separated() {
        let encoded = encode_commit_core(&commit_core()).unwrap();
        assert_eq!(encoded.len(), COMMIT_CORE_SIZE);
        assert_eq!(encoded[0], CommitKind::Join as u8);
        assert_eq!(encoded[33], GroupMode::Interactive as u8);
        assert_eq!(encoded[34], GroupMode::Interactive as u8);
        assert_eq!(encoded[35], MembershipMechanism::TreeKem as u8);
        assert_ne!(
            commit_sig_digest(&encoded).unwrap(),
            commit_hash(&encoded).unwrap()
        );

        let mut invalid = commit_core();
        invalid.new_group_mode = GroupMode::Lite;
        invalid.new_membership_mechanism = MembershipMechanism::TreeKem;
        assert_eq!(
            encode_commit_core(&invalid),
            Err(GroupError::InvalidModeMechanism {
                mode: GroupMode::Lite,
                mechanism: MembershipMechanism::TreeKem,
            })
        );

        invalid = commit_core();
        invalid.old_group_mode = None;
        assert_eq!(
            encode_commit_core(&invalid),
            Err(GroupError::InvalidCommitCore)
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
