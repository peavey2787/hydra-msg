use hydra_core::types::{Epoch, Secret32};

use crate::{
    change_payload_hash, commit_hash, commit_sig_digest, derive_epoch_key_for_context,
    direct_wrap_key_schedule_commitment, encode_change_payload, encode_commit_core,
    encode_governance_policy, encode_signature_set, governance_policy_hash, mode_policy_hash,
    roster_hash, treekem_key_schedule_commitment, update_path_hash, validate_governance_for_roster,
    validate_governance_policy, validate_mode_mechanism, validate_roster_for_mode,
    validate_signature_set, CommitCore, CommitKind, CommitSignature, GovernancePolicy, GroupError,
    GroupMode, GroupResult, GroupRole, GroupState, MemberId, MemberStatus, MembershipMechanism,
    MembershipPrivateState, ModePolicy, PublicLeaf, PublicTree, RosterEntry, StateVersion,
    UpdatePath,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitChange {
    Create {
        new_roster: Vec<RosterEntry>,
        new_governance_policy: GovernancePolicy,
        new_mode_policy: ModePolicy,
        new_tree_hash: [u8; 64],
    },
    Join {
        new_entry: RosterEntry,
    },
    Leave {
        member_id: MemberId,
    },
    RemoveOrRevoke {
        member_id: MemberId,
        reason_code: u16,
    },
    GovernanceChange {
        new_governance_policy: GovernancePolicy,
    },
    IdentityRotate {
        old_member_id: MemberId,
        new_entry: RosterEntry,
        rotation_digest: [u8; 64],
    },
    RoleChange {
        member_id: MemberId,
        new_role: GroupRole,
    },
    ModeChange {
        new_mode: GroupMode,
        new_mode_policy: ModePolicy,
    },
    TreeSelfUpdate {
        committer_member_id: MemberId,
    },
}

impl CommitChange {
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

pub struct CommitPlan {
    pub committer: MemberId,
    pub commit_nonce: [u8; 32],
    pub change: CommitChange,
    pub signatures: Vec<CommitSignature>,
    pub update_path: Option<UpdatePath>,
    pub direct_epoch_secret: Option<[u8; 32]>,
}

pub struct PreparedCommit {
    pub core: CommitCore,
    pub encoded_core: Vec<u8>,
    pub signature_digest: [u8; 64],
    pub commit_hash: [u8; 64],
    pub signatures: Vec<CommitSignature>,
    candidate: CandidateState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitInstallResult {
    Applied,
    Duplicate,
    Forked,
}

struct CandidateState {
    mode: GroupMode,
    mechanism: MembershipMechanism,
    epoch: Epoch,
    state_version: StateVersion,
    roster: Vec<RosterEntry>,
    roster_hash: [u8; 64],
    tree_hash: [u8; 64],
    governance_policy: GovernancePolicy,
    mode_policy: ModePolicy,
    public_tree: Option<PublicTree>,
    direct_epoch_secret: Option<Secret32>,
}

pub fn prepare_commit(state: &GroupState, plan: CommitPlan) -> GroupResult<PreparedCommit> {
    state.require_active()?;
    validate_parent_for_change(state, plan.committer, &plan.change)?;

    let transition = build_transition(state, &plan)?;
    if plan.change.kind() == CommitKind::Create {
        validate_governance_signatures(
            &transition.governance_policy,
            &transition.roster,
            &plan.signatures,
        )?;
    } else {
        validate_governance_signatures(&state.governance_policy, &state.roster, &plan.signatures)?;
    }
    validate_change_specific_signatures(&plan.change, &plan.signatures)?;
    let payload = build_change_payload(state, &plan.change)?;
    let encoded_payload = encode_change_payload(&payload)?;
    let payload_hash = change_payload_hash(&encoded_payload)?;
    let key_commitment = key_schedule_commitment(state, &transition, &plan)?;

    let canonical_governance = encode_governance_policy(&transition.governance_policy)?;
    let core = CommitCore {
        commit_kind: plan.change.kind(),
        group_id: state.group_id,
        old_group_mode: if plan.change.kind() == CommitKind::Create {
            None
        } else {
            Some(state.mode)
        },
        new_group_mode: transition.mode,
        new_membership_mechanism: transition.mechanism,
        old_epoch: state.epoch,
        new_epoch: transition.epoch,
        old_state_version: state.state_version,
        new_state_version: transition.state_version,
        parent_commit_hash: state.last_commit_hash,
        old_roster_hash: state.roster_hash,
        new_roster_hash: transition.roster_hash,
        old_tree_hash: state.tree_hash,
        new_tree_hash: transition.tree_hash,
        commit_nonce: plan.commit_nonce,
        change_payload_hash: payload_hash,
        key_schedule_commitment: key_commitment,
        governance_policy_hash: governance_policy_hash(&canonical_governance)?,
        mode_policy_hash: mode_policy_hash(transition.mode_policy)?,
    };
    let encoded_core = encode_commit_core(&core)?;
    let signature_digest = commit_sig_digest(&encoded_core)?;
    let commit_hash = commit_hash(&encoded_core)?;
    Ok(PreparedCommit {
        core,
        encoded_core,
        signature_digest,
        commit_hash,
        signatures: plan.signatures,
        candidate: transition,
    })
}

pub fn apply_prepared_commit(state: &mut GroupState, prepared: PreparedCommit) -> GroupResult<()> {
    state.require_active()?;
    if prepared.core.group_id != state.group_id
        || prepared.core.parent_commit_hash != state.last_commit_hash
        || prepared.core.old_roster_hash != state.roster_hash
        || prepared.core.old_tree_hash != state.tree_hash
        || prepared.core.old_epoch != state.epoch
        || prepared.core.old_state_version != state.state_version
        || (prepared.core.commit_kind != CommitKind::Create
            && prepared.core.old_group_mode != Some(state.mode))
    {
        return Err(GroupError::InvalidCommitParent);
    }
    if prepared.core.commit_kind == CommitKind::Create {
        validate_governance_signatures(
            &prepared.candidate.governance_policy,
            &prepared.candidate.roster,
            &prepared.signatures,
        )?;
    } else {
        validate_governance_signatures(
            &state.governance_policy,
            &state.roster,
            &prepared.signatures,
        )?;
    }
    verify_prepared_commit_integrity(&prepared)?;

    state.previous_commit_hash = state.last_commit_hash;
    state.mode = prepared.candidate.mode;
    state.mechanism = prepared.candidate.mechanism;
    state.epoch = prepared.candidate.epoch;
    state.state_version = prepared.candidate.state_version;
    state.last_commit_hash = prepared.commit_hash;
    state.roster_hash = prepared.candidate.roster_hash;
    state.tree_hash = prepared.candidate.tree_hash;
    state.governance_policy = prepared.candidate.governance_policy;
    state.mode_policy = prepared.candidate.mode_policy;
    state.roster = prepared.candidate.roster;

    let sender_epoch_key = match (&prepared.candidate.direct_epoch_secret, state.mechanism) {
        (Some(secret), MembershipMechanism::DirectWrap) => Some(derive_epoch_key_for_context(
            secret,
            &state.epoch_key_context(),
        )?),
        _ => None,
    };
    install_membership_material(
        state,
        prepared.candidate.public_tree,
        prepared.candidate.direct_epoch_secret,
    );
    if let Some(epoch_key) = sender_epoch_key.as_ref() {
        state.install_epoch_sender_chains(epoch_key)?;
    } else {
        state.sender_chains.clear();
        state.replay_state.clear();
    }
    Ok(())
}

pub fn install_prepared_commit(
    state: &mut GroupState,
    prepared: PreparedCommit,
) -> GroupResult<CommitInstallResult> {
    state.require_active()?;
    verify_prepared_commit_integrity(&prepared)?;

    if prepared.commit_hash == state.last_commit_hash
        && prepared.core.new_epoch == state.epoch
        && prepared.core.new_state_version == state.state_version
        && prepared.core.new_roster_hash == state.roster_hash
        && prepared.core.new_tree_hash == state.tree_hash
    {
        return Ok(CommitInstallResult::Duplicate);
    }

    if prepared.core.parent_commit_hash == state.last_commit_hash
        && prepared.core.old_epoch == state.epoch
        && prepared.core.old_state_version == state.state_version
    {
        apply_prepared_commit(state, prepared)?;
        return Ok(CommitInstallResult::Applied);
    }

    if prepared.core.parent_commit_hash == state.previous_commit_hash
        && prepared.core.new_epoch == state.epoch
        && prepared.core.new_state_version == state.state_version
        && prepared.commit_hash != state.last_commit_hash
    {
        state.mark_forked();
        return Ok(CommitInstallResult::Forked);
    }

    Err(GroupError::InvalidCommitParent)
}

fn verify_prepared_commit_integrity(prepared: &PreparedCommit) -> GroupResult<()> {
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

fn validate_change_specific_signatures(
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

fn validate_parent_for_change(
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

fn build_transition(state: &GroupState, plan: &CommitPlan) -> GroupResult<CandidateState> {
    let (new_epoch, new_state_version) = next_transition_counters(state, plan.change.kind())?;
    let mut mode = state.mode;
    let mut mechanism = state.mechanism;
    let mut roster = state.roster.clone();
    let mut governance_policy = state.governance_policy.clone();
    let mut mode_policy = state.mode_policy;
    let mut tree_hash = state.tree_hash;
    let mut public_tree = None;
    let mut direct_epoch_secret = None;

    match &plan.change {
        CommitChange::Create {
            new_roster,
            new_governance_policy,
            new_mode_policy,
            new_tree_hash,
        } => {
            roster = new_roster.clone();
            governance_policy = new_governance_policy.clone();
            mode_policy = *new_mode_policy;
            tree_hash = *new_tree_hash;
        }
        CommitChange::Join { new_entry } => {
            if roster
                .iter()
                .any(|entry| entry.member_id == new_entry.member_id)
            {
                return Err(GroupError::MemberAlreadyExists {
                    member_id: new_entry.member_id,
                });
            }
            roster.push(new_entry.clone());
        }
        CommitChange::Leave { member_id } => {
            mark_removed(&mut roster, *member_id, new_epoch)?;
            prune_removed_governance_signer(&mut governance_policy, *member_id);
        }
        CommitChange::RemoveOrRevoke { member_id, .. } => {
            mark_removed(&mut roster, *member_id, new_epoch)?;
            prune_removed_governance_signer(&mut governance_policy, *member_id);
        }
        CommitChange::GovernanceChange {
            new_governance_policy,
        } => {
            governance_policy = new_governance_policy.clone();
        }
        CommitChange::IdentityRotate {
            old_member_id,
            new_entry,
            ..
        } => {
            mark_removed(&mut roster, *old_member_id, new_epoch)?;
            if roster
                .iter()
                .any(|entry| entry.member_id == new_entry.member_id)
            {
                return Err(GroupError::MemberAlreadyExists {
                    member_id: new_entry.member_id,
                });
            }
            roster.push(new_entry.clone());
        }
        CommitChange::RoleChange {
            member_id,
            new_role,
        } => {
            if !new_role.is_active_in_mode(mode) {
                return Err(GroupError::InvalidRoleForMode {
                    mode,
                    role: *new_role,
                });
            }
            let entry = roster
                .iter_mut()
                .find(|entry| entry.member_id == *member_id)
                .ok_or(GroupError::MemberNotFound {
                    member_id: *member_id,
                })?;
            if entry.status != MemberStatus::Active {
                return Err(GroupError::MemberInactive {
                    member_id: *member_id,
                });
            }
            entry.role = *new_role;
        }
        CommitChange::ModeChange {
            new_mode,
            new_mode_policy,
        } => {
            mode = *new_mode;
            mechanism = new_mode.required_mechanism();
            mode_policy = *new_mode_policy;
            remap_roster_slots_for_mode(mode, &mut roster)?;
            if mechanism == MembershipMechanism::DirectWrap {
                tree_hash = [0; 64];
            }
        }
        CommitChange::TreeSelfUpdate { .. } => {}
    }

    validate_mode_mechanism(mode, mechanism)?;
    validate_roster_for_mode(mode, new_epoch, &roster)?;
    validate_governance_for_roster(&governance_policy, &roster)?;
    let encoded_roster = crate::encode_roster(mode, &roster)?;
    let roster_hash = roster_hash(&encoded_roster)?;

    match mechanism {
        MembershipMechanism::TreeKem => {
            if plan.change.kind() != CommitKind::Create {
                let update_path = plan
                    .update_path
                    .as_ref()
                    .ok_or(GroupError::MissingUpdatePath)?;
                tree_hash = update_path.candidate_tree_hash;
                public_tree = apply_update_path_to_public_tree(state, update_path, &plan.change)?;
            }
        }
        MembershipMechanism::DirectWrap => {
            let secret = plan
                .direct_epoch_secret
                .ok_or(GroupError::MissingEpochSecret)?;
            direct_epoch_secret = Some(Secret32::new(secret));
        }
    }

    Ok(CandidateState {
        mode,
        mechanism,
        epoch: new_epoch,
        state_version: new_state_version,
        roster,
        roster_hash,
        tree_hash,
        governance_policy,
        mode_policy,
        public_tree,
        direct_epoch_secret,
    })
}

fn next_transition_counters(
    state: &GroupState,
    kind: CommitKind,
) -> GroupResult<(Epoch, StateVersion)> {
    if kind == CommitKind::Create {
        if state.epoch.0 != 0 || state.state_version.0 != 0 {
            return Err(GroupError::InvalidCommitParent);
        }
        return Ok((Epoch(0), StateVersion(0)));
    }
    let epoch = state
        .epoch
        .0
        .checked_add(1)
        .map(Epoch)
        .ok_or(GroupError::CounterExhausted)?;
    let state_version = state
        .state_version
        .0
        .checked_add(1)
        .map(StateVersion)
        .ok_or(GroupError::CounterExhausted)?;
    Ok((epoch, state_version))
}

fn build_change_payload<'a>(
    state: &'a GroupState,
    change: &'a CommitChange,
) -> GroupResult<crate::ChangePayload<'a>> {
    match change {
        CommitChange::Create {
            new_governance_policy,
            new_mode_policy,
            ..
        } => Ok(crate::ChangePayload::Create {
            new_governance_policy,
            new_mode_policy: *new_mode_policy,
        }),
        CommitChange::Join { new_entry } => Ok(crate::ChangePayload::Join { new_entry }),
        CommitChange::Leave { member_id } => Ok(crate::ChangePayload::Leave {
            member_id: *member_id,
        }),
        CommitChange::RemoveOrRevoke {
            member_id,
            reason_code,
        } => Ok(crate::ChangePayload::RemoveOrRevoke {
            member_id: *member_id,
            reason_code: *reason_code,
        }),
        CommitChange::GovernanceChange {
            new_governance_policy,
        } => Ok(crate::ChangePayload::GovernanceChange {
            new_governance_policy,
        }),
        CommitChange::IdentityRotate {
            old_member_id,
            new_entry,
            rotation_digest,
        } => Ok(crate::ChangePayload::IdentityRotate {
            old_member_id: *old_member_id,
            new_entry,
            rotation_digest: *rotation_digest,
        }),
        CommitChange::RoleChange {
            member_id,
            new_role,
        } => {
            let old_role = state
                .roster
                .iter()
                .find(|entry| entry.member_id == *member_id)
                .ok_or(GroupError::MemberNotFound {
                    member_id: *member_id,
                })?
                .role;
            Ok(crate::ChangePayload::RoleChange {
                member_id: *member_id,
                old_role,
                new_role: *new_role,
            })
        }
        CommitChange::ModeChange {
            new_mode,
            new_mode_policy,
        } => Ok(crate::ChangePayload::ModeChange {
            old_mode: state.mode,
            new_mode: *new_mode,
            new_mode_policy: *new_mode_policy,
        }),
        CommitChange::TreeSelfUpdate {
            committer_member_id,
        } => Ok(crate::ChangePayload::TreeSelfUpdate {
            committer_member_id: *committer_member_id,
        }),
    }
}

fn key_schedule_commitment(
    state: &GroupState,
    transition: &CandidateState,
    plan: &CommitPlan,
) -> GroupResult<[u8; 64]> {
    match transition.mechanism {
        MembershipMechanism::TreeKem => {
            if plan.change.kind() == CommitKind::Create {
                Ok(treekem_key_schedule_commitment(
                    state.group_id,
                    transition.mode,
                    transition.epoch,
                    transition.tree_hash,
                    [0; 64],
                ))
            } else {
                let update_hash = update_path_hash(
                    plan.update_path
                        .as_ref()
                        .ok_or(GroupError::MissingUpdatePath)?,
                )?;
                Ok(treekem_key_schedule_commitment(
                    state.group_id,
                    transition.mode,
                    transition.epoch,
                    transition.tree_hash,
                    update_hash,
                ))
            }
        }
        MembershipMechanism::DirectWrap => {
            let secret = transition
                .direct_epoch_secret
                .as_ref()
                .ok_or(GroupError::MissingEpochSecret)?;
            Ok(direct_wrap_key_schedule_commitment(
                state.group_id,
                transition.mode,
                transition.epoch,
                plan.commit_nonce,
                secret,
            ))
        }
    }
}

fn mark_removed(
    roster: &mut [RosterEntry],
    member_id: MemberId,
    removed_epoch: Epoch,
) -> GroupResult<()> {
    let entry = roster
        .iter_mut()
        .find(|entry| entry.member_id == member_id)
        .ok_or(GroupError::MemberNotFound { member_id })?;
    if entry.status != MemberStatus::Active {
        return Err(GroupError::MemberInactive { member_id });
    }
    entry.status = MemberStatus::Removed;
    entry.removed_epoch = removed_epoch;
    Ok(())
}

fn prune_removed_governance_signer(policy: &mut GovernancePolicy, member_id: MemberId) {
    policy
        .authorized_signers
        .retain(|authorized| *authorized != member_id);
}

fn removed_member_for_change(change: &CommitChange) -> Option<MemberId> {
    match change {
        CommitChange::Leave { member_id } | CommitChange::RemoveOrRevoke { member_id, .. } => {
            Some(*member_id)
        }
        _ => None,
    }
}

fn remap_roster_slots_for_mode(mode: GroupMode, roster: &mut [RosterEntry]) -> GroupResult<()> {
    let mut active_indices = roster
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.status == MemberStatus::Active).then_some(index))
        .collect::<Vec<_>>();
    active_indices.sort_by_key(|index| roster[*index].member_id.0);
    match mode.required_mechanism() {
        MembershipMechanism::TreeKem => {
            if active_indices.len() > mode.max_roster_entries() {
                return Err(GroupError::InvalidRoster);
            }
            for (slot, index) in active_indices.into_iter().enumerate() {
                roster[index].tree_leaf_slot =
                    u32::try_from(slot).map_err(|_| GroupError::CounterExhausted)?;
            }
        }
        MembershipMechanism::DirectWrap => {
            for index in active_indices {
                roster[index].tree_leaf_slot = u32::MAX;
            }
        }
    }
    Ok(())
}

fn apply_update_path_to_public_tree(
    state: &GroupState,
    update_path: &UpdatePath,
    change: &CommitChange,
) -> GroupResult<Option<PublicTree>> {
    let target_mode = match change {
        CommitChange::ModeChange { new_mode, .. } => *new_mode,
        _ => state.mode,
    };
    let old_tree = match &state.membership {
        MembershipPrivateState::TreeKem { public_tree, .. } => Some(public_tree),
        _ => None,
    };
    let mut candidate = if matches!(change, CommitChange::ModeChange { .. }) {
        build_mode_change_public_tree(state, target_mode, old_tree)?
    } else {
        old_tree.cloned().ok_or(GroupError::InvalidState)?
    };
    if candidate.mode != target_mode || update_path.leaf_capacity != candidate.leaf_capacity {
        return Err(GroupError::InvalidUpdatePath);
    }
    if let Some(member_id) = removed_member_for_change(change) {
        let entry = state
            .roster
            .iter()
            .find(|entry| entry.member_id == member_id)
            .ok_or(GroupError::MemberNotFound { member_id })?;
        candidate.vacate_leaf(entry.tree_leaf_slot)?;
    }
    if let CommitChange::RoleChange {
        member_id,
        new_role,
    } = change
    {
        let entry = state
            .roster
            .iter()
            .find(|entry| entry.member_id == *member_id)
            .ok_or(GroupError::MemberNotFound {
                member_id: *member_id,
            })?;
        candidate.update_leaf_role(entry.tree_leaf_slot, *new_role)?;
    }
    for node in &update_path.updated_nodes {
        candidate.set_node_key(node.node_index, Some(node.node_key.clone()))?;
    }
    if candidate.tree_hash()? != update_path.candidate_tree_hash {
        return Err(GroupError::InvalidUpdatePath);
    }
    Ok(Some(candidate))
}

fn build_mode_change_public_tree(
    state: &GroupState,
    target_mode: GroupMode,
    old_tree: Option<&PublicTree>,
) -> GroupResult<PublicTree> {
    let mut roster = state.roster.clone();
    remap_roster_slots_for_mode(target_mode, &mut roster)?;
    let mut tree = PublicTree::new(target_mode, Some(state.epoch))?;
    for entry in roster
        .iter()
        .filter(|entry| entry.status == MemberStatus::Active)
    {
        let old_leaf = old_tree.and_then(|tree| {
            tree.nodes
                .iter()
                .filter_map(|node| node.leaf.as_ref())
                .find(|leaf| leaf.member_id == entry.member_id)
        });
        let leaf = PublicLeaf {
            member_id: entry.member_id,
            device_identity_fingerprint: entry.device_identity_fingerprint,
            role: entry.role,
            generation: old_leaf.map_or(0, |leaf| leaf.generation),
            node_key: old_leaf.and_then(|leaf| leaf.node_key.clone()),
        };
        tree.occupy_leaf(entry.tree_leaf_slot, leaf)?;
    }
    Ok(tree)
}

fn install_membership_material(
    state: &mut GroupState,
    public_tree: Option<PublicTree>,
    direct_epoch_secret: Option<Secret32>,
) {
    match (state.mechanism, public_tree, direct_epoch_secret) {
        (MembershipMechanism::TreeKem, Some(public_tree), _) => match &mut state.membership {
            MembershipPrivateState::TreeKem {
                public_tree: current,
                ..
            } => *current = public_tree,
            _ => {
                state.membership = MembershipPrivateState::TreeKem {
                    public_tree,
                    private_path: crate::PrivatePath::default(),
                };
            }
        },
        (MembershipMechanism::DirectWrap, _, Some(epoch_secret)) => {
            state.membership = MembershipPrivateState::DirectWrap { epoch_secret };
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GroupPhase;
    use hydra_core::types::{GroupId, IdentityFingerprint};

    fn group_id() -> GroupId {
        GroupId([0x42; 32])
    }

    fn member(value: u8) -> MemberId {
        MemberId([value; 32])
    }

    fn fingerprint(value: u8) -> IdentityFingerprint {
        IdentityFingerprint([value; 32])
    }

    fn entry(member_value: u8, fingerprint_value: u8, role: GroupRole) -> RosterEntry {
        RosterEntry {
            member_id: member(member_value),
            device_identity_fingerprint: fingerprint(fingerprint_value),
            role,
            status: MemberStatus::Active,
            tree_leaf_slot: u32::from(member_value),
            joined_epoch: Epoch(1),
            removed_epoch: Epoch(0),
        }
    }

    fn lite_state() -> GroupState {
        GroupState::new_validated(crate::GroupStateConfig {
            group_id: group_id(),
            mode: GroupMode::Lite,
            mechanism: MembershipMechanism::DirectWrap,
            epoch: Epoch(1),
            state_version: StateVersion(1),
            governance_policy: GovernancePolicy::single_signer(member(1)),
            mode_policy: ModePolicy::default(),
            roster: vec![entry(1, 1, GroupRole::Member)],
        })
        .unwrap()
    }

    fn signature(signer: MemberId) -> CommitSignature {
        CommitSignature {
            signer,
            signature: [0x5a; hydra_core::ML_DSA_65_SIG_SIZE],
        }
    }

    fn role_change_plan(new_role: GroupRole) -> CommitPlan {
        CommitPlan {
            committer: member(1),
            commit_nonce: [0x77; 32],
            change: CommitChange::RoleChange {
                member_id: member(1),
                new_role,
            },
            signatures: vec![signature(member(1))],
            update_path: None,
            direct_epoch_secret: Some([0x88; 32]),
        }
    }

    #[test]
    fn governance_signature_threshold_order_and_authorization_are_enforced() {
        let state = lite_state();
        assert_eq!(
            validate_governance_signatures(&state.governance_policy, &state.roster, &[]),
            Err(GroupError::InvalidSignatureSet)
        );
        let unauthorized = vec![signature(member(2))];
        assert_eq!(
            validate_governance_signatures(&state.governance_policy, &state.roster, &unauthorized),
            Err(GroupError::InvalidGovernanceSigner { signer: member(2) })
        );
        assert!(validate_governance_signatures(
            &state.governance_policy,
            &state.roster,
            &[signature(member(1))]
        )
        .is_ok());
    }

    #[test]
    fn lite_role_change_prepares_and_applies_atomically() {
        let mut state = lite_state();
        let before_parent = state.last_commit_hash;
        let prepared = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
        assert_eq!(prepared.core.old_epoch, Epoch(1));
        assert_eq!(prepared.core.new_epoch, Epoch(2));
        assert_eq!(prepared.core.old_state_version, StateVersion(1));
        assert_eq!(prepared.core.new_state_version, StateVersion(2));
        assert_eq!(prepared.core.parent_commit_hash, before_parent);
        assert_ne!(prepared.commit_hash, [0; 64]);
        assert_ne!(prepared.signature_digest, prepared.commit_hash);

        apply_prepared_commit(&mut state, prepared).unwrap();
        assert_eq!(state.epoch, Epoch(2));
        assert_eq!(state.state_version, StateVersion(2));
        assert_eq!(state.roster[0].role, GroupRole::Moderator);
        assert_ne!(state.last_commit_hash, before_parent);
        assert!(matches!(
            &state.membership,
            MembershipPrivateState::DirectWrap { .. }
        ));
        assert_eq!(state.sender_chains.len(), 1);
        assert_eq!(state.replay_state.senders.len(), 1);
        let first = state.next_sender_message_step(member(1)).unwrap();
        assert_eq!(first.sender, member(1));
        assert_eq!(first.index, 0);
        assert_eq!(state.sender_chains.next_index(member(1)), Some(1));
    }

    #[test]
    fn invalid_commit_preserves_parent_state() {
        let state = lite_state();
        let before = (
            state.epoch,
            state.state_version,
            state.roster.clone(),
            state.roster_hash,
        );
        assert_eq!(
            prepare_commit(&state, role_change_plan(GroupRole::Audience)).map(|_| ()),
            Err(GroupError::InvalidRoleForMode {
                mode: GroupMode::Lite,
                role: GroupRole::Audience,
            })
        );
        assert_eq!(
            (
                state.epoch,
                state.state_version,
                state.roster.clone(),
                state.roster_hash
            ),
            before
        );
    }

    #[test]
    fn non_create_counter_overflow_rejects_before_state_change() {
        let mut state = lite_state();
        state.epoch = Epoch(u64::MAX);
        let before = (
            state.epoch,
            state.state_version,
            state.roster.clone(),
            state.roster_hash,
        );
        assert_eq!(
            prepare_commit(&state, role_change_plan(GroupRole::Moderator)).map(|_| ()),
            Err(GroupError::CounterExhausted)
        );
        assert_eq!(
            (
                state.epoch,
                state.state_version,
                state.roster.clone(),
                state.roster_hash
            ),
            before
        );
    }

    #[test]
    fn create_uses_epoch_and_state_version_zero() {
        let state = GroupState::new_empty(
            group_id(),
            GroupMode::Lite,
            MembershipMechanism::DirectWrap,
            GovernancePolicy::single_signer(member(1)),
            ModePolicy::default(),
        )
        .unwrap();
        let mut created = entry(1, 1, GroupRole::Member);
        created.joined_epoch = Epoch(0);
        let plan = CommitPlan {
            committer: member(1),
            commit_nonce: [0x11; 32],
            change: CommitChange::Create {
                new_roster: vec![created],
                new_governance_policy: GovernancePolicy::single_signer(member(1)),
                new_mode_policy: ModePolicy::default(),
                new_tree_hash: [0; 64],
            },
            signatures: vec![signature(member(1))],
            update_path: None,
            direct_epoch_secret: Some([0x33; 32]),
        };
        let prepared = prepare_commit(&state, plan).unwrap();
        assert_eq!(prepared.core.old_group_mode, None);
        assert_eq!(prepared.core.old_epoch, Epoch(0));
        assert_eq!(prepared.core.new_epoch, Epoch(0));
        assert_eq!(prepared.core.old_state_version, StateVersion(0));
        assert_eq!(prepared.core.new_state_version, StateVersion(0));
    }

    #[test]
    fn install_reports_duplicate_without_mutation() {
        let mut state = lite_state();
        let first = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
        let duplicate = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
        assert_eq!(
            install_prepared_commit(&mut state, first),
            Ok(CommitInstallResult::Applied)
        );
        let before = (
            state.epoch,
            state.state_version,
            state.last_commit_hash,
            state.phase,
        );
        assert_eq!(
            install_prepared_commit(&mut state, duplicate),
            Ok(CommitInstallResult::Duplicate)
        );
        assert_eq!(
            (
                state.epoch,
                state.state_version,
                state.last_commit_hash,
                state.phase
            ),
            before
        );
    }

    #[test]
    fn sibling_commit_marks_group_forked_and_wipes_private_material() {
        let mut state = lite_state();
        let first = prepare_commit(&state, role_change_plan(GroupRole::Moderator)).unwrap();
        let mut sibling_plan = role_change_plan(GroupRole::Moderator);
        sibling_plan.commit_nonce = [0x78; 32];
        sibling_plan.direct_epoch_secret = Some([0x89; 32]);
        let sibling = prepare_commit(&state, sibling_plan).unwrap();

        assert_eq!(
            install_prepared_commit(&mut state, first),
            Ok(CommitInstallResult::Applied)
        );
        assert!(matches!(
            state.membership,
            MembershipPrivateState::DirectWrap { .. }
        ));
        assert_eq!(
            install_prepared_commit(&mut state, sibling),
            Ok(CommitInstallResult::Forked)
        );
        assert_eq!(state.phase, GroupPhase::Forked);
        assert!(matches!(state.membership, MembershipPrivateState::Empty));
        assert_eq!(
            state.require_sender(member(1)),
            Err(GroupError::InvalidState)
        );
    }

    #[test]
    fn closed_or_forked_groups_reject_commit_installation() {
        let mut closed = lite_state();
        let prepared_for_closed =
            prepare_commit(&closed, role_change_plan(GroupRole::Moderator)).unwrap();
        closed.close();
        assert_eq!(
            install_prepared_commit(&mut closed, prepared_for_closed),
            Err(GroupError::InvalidState)
        );

        let mut forked = lite_state();
        let prepared_for_forked =
            prepare_commit(&forked, role_change_plan(GroupRole::Moderator)).unwrap();
        forked.mark_forked();
        assert_eq!(
            install_prepared_commit(&mut forked, prepared_for_forked),
            Err(GroupError::InvalidState)
        );
    }

    #[test]
    fn treekem_commit_requires_update_path() {
        let state = GroupState::new_validated(crate::GroupStateConfig {
            group_id: group_id(),
            mode: GroupMode::Interactive,
            mechanism: MembershipMechanism::TreeKem,
            epoch: Epoch(1),
            state_version: StateVersion(1),
            governance_policy: GovernancePolicy::single_signer(member(1)),
            mode_policy: ModePolicy::default(),
            roster: vec![entry(1, 1, GroupRole::Member)],
        })
        .unwrap();
        let plan = CommitPlan {
            committer: member(1),
            commit_nonce: [0x11; 32],
            change: CommitChange::TreeSelfUpdate {
                committer_member_id: member(1),
            },
            signatures: vec![signature(member(1))],
            update_path: None,
            direct_epoch_secret: None,
        };
        assert_eq!(
            prepare_commit(&state, plan).map(|_| ()),
            Err(GroupError::MissingUpdatePath)
        );
    }
}
