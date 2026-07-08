use crate::types::{GroupMode, GroupRole, MemberId, MembershipMechanism};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupError {
    CounterExhausted,
    InvalidDiscriminant {
        type_name: &'static str,
        value: u8,
    },
    InvalidModeMechanism {
        mode: GroupMode,
        mechanism: MembershipMechanism,
    },
    InvalidLength {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidRoster,
    InvalidTreeSlot {
        slot: u32,
        capacity: u32,
    },
    InvalidTreeNode {
        node_index: u32,
    },
    InvalidTreeNodeKeyFlag {
        flag: u8,
    },
    InvalidTreePath,
    InvalidTreeResolution,
    InvalidUpdatePath,
    InvalidSenderChain,
    InvalidEnvelope,
    AuthenticationFailed,
    InvalidGroupSignature,
    ReplayDetected,
    MessageTooOld,
    MessageTooFarAhead,
    InvalidRoleForMode {
        mode: GroupMode,
        role: GroupRole,
    },
    InvalidGovernancePolicy,
    InvalidSignatureSet,
    InvalidCommitCore,
    InvalidCommitParent,
    InsufficientGovernanceSignatures,
    MissingUpdatePath,
    MissingEpochSecret,
    InvalidState,
    InvalidGovernanceSigner {
        signer: MemberId,
    },
    MemberAlreadyExists {
        member_id: MemberId,
    },
    MemberNotFound {
        member_id: MemberId,
    },
    MemberInactive {
        member_id: MemberId,
    },
    SenderNotAllowed {
        member_id: MemberId,
    },
    Unsupported(&'static str),
}

pub type GroupResult<T> = Result<T, GroupError>;
