use super::primitives::is_strictly_ordered_member_ids;
use crate::{GovernancePolicy, GroupError, GroupResult, ModePolicy};
use hydra_core::MAX_GOVERNANCE_SIGNERS;

pub const MODE_POLICY_SIZE: usize = 12;

#[must_use]
pub fn encode_mode_policy(policy: ModePolicy) -> [u8; MODE_POLICY_SIZE] {
    policy.bytes
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::test_support::{member, sorted_governance},
        GroupError,
    };

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
}
