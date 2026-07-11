//! Epoch-based group messaging and TreeKEM-style rekey implementation.
//!
//! This crate is a first-class checked workspace member. Its focused modules own
//! group commit, TreeKEM, sender-chain, and welcome machinery.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod commit;
pub mod distribution;
pub mod epoch;
pub mod error;
pub mod membership;
pub mod message;
pub mod private_path;
pub mod public_tree;
pub mod rekey;
pub mod state;
pub mod types;
pub mod validation;

pub use canonical::{
    change_payload_hash, checked_u16_be, checked_u32_be, commit_confirmation_tag, commit_hash,
    commit_sig_digest, direct_wrap_key_schedule_commitment, encode_change_payload,
    encode_commit_core, encode_governance_policy, encode_mode_policy, encode_roster,
    encode_roster_entry, encode_signature_set, governance_policy_hash, lp, member_id,
    mode_policy_hash, roster_hash, treekem_key_schedule_commitment, u16_be, u32_be, u64_be,
    validate_governance_policy, validate_roster_for_canonical_encoding, validate_signature_set,
    verify_commit_confirmation_tag, ChangePayload, CommitCore, CommitSignature, COMMIT_CORE_SIZE,
    MODE_POLICY_SIZE, ROSTER_ENTRY_SIZE,
};
pub use commit::{
    apply_prepared_commit, install_prepared_commit, prepare_commit, validate_governance_signatures,
    CommitChange, CommitInstallResult, CommitPlan, PreparedCommit,
};
pub use distribution::{
    encode_update_path, encrypt_path_updates, resolve_subtree, resolve_update_path_targets,
    update_path_hash, wrap_context, PathCiphertext, PathSecretTarget, ResolvedPathTarget,
    TreeKemWrapContext, UpdatePath, WRAPPED_PATH_SECRET_SIZE,
};
pub use epoch::{
    derive_epoch_key, derive_epoch_key_for_context, derive_sender_chain_key,
    derive_sender_message_step, next_epoch, sender_chain_commitment, EpochKeyContext,
    SenderMessageStep,
};
pub use error::{GroupError, GroupResult};
pub use message::{
    group_data_signature_digest, identity_fingerprint, GroupOutboundMessage, GroupReceivedMessage,
};
pub use private_path::{
    derive_and_install_path, parent_path, DerivedPublicPathNode, PrivatePath,
    PrivatePathNodeSecret, TreeKemPathContext, TreeKemPathUpdate,
};
pub use public_tree::{
    copath, direct_path, leaf_capacity_for_mode, leaf_node_index, left_child, occupied_leaf_hash,
    parent_index, parent_node_hash, right_child, sibling_index, vacant_leaf_hash,
    validate_node_key_flag, AffectedPathHash, PublicLeaf, PublicNodeKey, PublicTree,
    PublicTreeNode, NODE_KEY_ABSENT, NODE_KEY_PRESENT, ROOT_NODE_INDEX,
};
pub use state::{
    AcceptedGroupMessage, GroupReplayState, GroupReplayStateSnapshot, GroupState, GroupStateConfig,
    GroupStateSnapshot, MembershipPrivateState, MembershipPrivateStateSnapshot,
    PrivatePathNodeSecretSnapshot, SenderChainCursor, SenderChainCursorSnapshot, SenderChainState,
    SenderChainStateSnapshot, SenderReplayState, SenderReplayStateSnapshot,
    SkippedGroupMessageKeySnapshot,
};
pub use types::{
    mechanism_for_mode, validate_mode_mechanism, CommitKind, GovernancePolicy, GroupContext,
    GroupMode, GroupPhase, GroupRole, MemberId, MemberStatus, MembershipMechanism, ModePolicy,
    RosterEntry, StateVersion,
};

pub use validation::{
    ensure_active_member, ensure_member_absent, ensure_sender_allowed, roster_stats,
    validate_governance_for_roster, validate_roster_for_mode, RosterStats,
};

#[cfg(test)]
mod tests;
