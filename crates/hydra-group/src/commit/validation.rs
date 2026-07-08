use crate::{
    commit_hash, commit_sig_digest, encode_commit_core, encode_signature_set,
    validate_governance_policy, validate_signature_set, CommitSignature, GovernancePolicy,
    GroupError, GroupResult, GroupState, MemberId, MemberStatus, RosterEntry,
};

use super::types::{CommitChange, PreparedCommit};

pub(crate) fn verify_prepared_commit_integrity(prepared: &PreparedCommit) -> GroupResult<()> {
    let encoded = encode_commit_core(&prepared.core)?;
    if encoded != prepared.encoded_core
        || commit_sig_digest(&encoded)? != prepared.signature_digest
        || commit_hash(&encoded)? != prepared.commit_hash
    {
        return Err(GroupError::InvalidCommitCore);
    }
    Ok(())
}

pub fn validate_governance_signatures(
    policy: &GovernancePolicy,
    roster: &[RosterEntry],
    signatures: &[CommitSignature],
) -> GroupResult<()> {
    validate_governance_policy(policy)?;
    validate_signature_set(signatures)?;
    encode_signature_set(signatures)?;
    if signatures.len() < usize::from(policy.threshold) {
        return Err(GroupError::InsufficientGovernanceSignatures);
    }
    for signature in signatures {
        if !policy
            .authorized_signers
            .iter()
            .any(|signer| signer == &signature.signer)
        {
            return Err(GroupError::InvalidGovernanceSigner {
                signer: signature.signer,
            });
        }
        let Some(entry) = roster
            .iter()
            .find(|entry| entry.member_id == signature.signer)
        else {
            return Err(GroupError::InvalidGovernanceSigner {
                signer: signature.signer,
            });
        };
        if entry.status != MemberStatus::Active {
            return Err(GroupError::InvalidGovernanceSigner {
                signer: signature.signer,
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_change_specific_signatures(
    change: &CommitChange,
    signatures: &[CommitSignature],
) -> GroupResult<()> {
    if let CommitChange::Leave { member_id } = change {
        if !signatures
            .iter()
            .any(|signature| signature.signer == *member_id)
        {
            return Err(GroupError::InvalidCommitCore);
        }
    }
    Ok(())
}

pub(crate) fn validate_parent_for_change(
    state: &GroupState,
    committer: MemberId,
    change: &CommitChange,
) -> GroupResult<()> {
    match change {
        CommitChange::Create { .. } => {
            if state.epoch.0 != 0
                || state.state_version.0 != 0
                || !state.roster.is_empty()
                || state.last_commit_hash != [0; 64]
            {
                return Err(GroupError::InvalidCommitParent);
            }
        }
        CommitChange::Leave { member_id } => {
            if *member_id != committer {
                return Err(GroupError::InvalidCommitCore);
            }
            state.require_sender(committer)?;
        }
        CommitChange::TreeSelfUpdate {
            committer_member_id,
        } => {
            if *committer_member_id != committer {
                return Err(GroupError::InvalidCommitCore);
            }
            state.require_sender(committer)?;
        }
        _ => {
            state.require_sender(committer)?;
        }
    }
    Ok(())
}
