use super::primitives::u64_be;
use crate::{CommitKind, GroupError, GroupMode, GroupResult, MembershipMechanism, StateVersion};
use hydra_core::types::{Epoch, GroupId};

pub const COMMIT_CORE_SIZE: usize = 676;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::{
            hashes::{commit_hash, commit_sig_digest},
            test_support::commit_core,
        },
        CommitKind, GroupError, GroupMode, MembershipMechanism,
    };

    #[test]
    fn commit_core_encoding_is_exact_size() {
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
}
