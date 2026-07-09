# HYDRA-MSG v1 Rust type contract

## Navigation

- [Main README](../../README.md)
- [Spec document index](../spec/README.md)
- [Protocol spec](../spec/protocol-spec.md)
- [Threat model](../spec/threat-model.md)
- [Security proof sketch](../spec/security-proof-sketch.md)
- [State machines](../spec/state-machines.md)
- [Envelope serialization](../spec/envelope-serialization.md)
- [Chain-key evolution](../spec/chain-key-evolution.md)
- [TreeKEM profile](../spec/tree-kem.md)
- [Group modes](../spec/group-modes.md)
- [Group rekey](../spec/group-rekey.md)
- [Anonymous authorization](../spec/anonymous-authorization.md)

These are logical reference types. Wire encoding is exclusively the
byte-indexed format in `envelope-serialization.md`; no type in this file may be
cast, transmuted, or serialized as a native Rust struct.

Crate ownership is singular: `hydra-core` owns the constants, closed wire
discriminants, and shared logical types in this contract. `hydra-envelope`
owns outer-header and envelope encoding/decoding. Other crates import these
definitions and MUST NOT redeclare or fork them.

## 1. Constants

```rust
pub const OUTER_HEADER_SIZE: usize = 64;
pub const AEAD_TAG_SIZE: usize = 16;
pub const INNER_HEADER_SIZE: usize = 96;
pub const LITE_ENVELOPE_SIZE: usize = 4_096;
pub const STANDARD_ENVELOPE_SIZE: usize = 32_768;
pub const FULL_ENVELOPE_SIZE: usize = 147_456;
pub const LITE_MAX_CONTENT_SIZE: usize = 3_920;
pub const STANDARD_MAX_CONTENT_SIZE: usize = 32_592;
pub const FULL_MAX_CONTENT_SIZE: usize = 147_280;

pub const SUITE_ID: [u8; 16] = *b"HYDRA1-MK768-M65";
pub const X25519_SIZE: usize = 32;
pub const ML_KEM_768_EK_SIZE: usize = 1_184;
pub const ML_KEM_768_CT_SIZE: usize = 1_088;
pub const ML_KEM_SHARED_SECRET_SIZE: usize = 32;
pub const ML_DSA_65_VK_SIZE: usize = 1_952;
pub const ML_DSA_65_SIG_SIZE: usize = 3_309;
pub const HASH_SIZE: usize = 32;
pub const TRANSCRIPT_HASH_SIZE: usize = 64;
pub const SESSION_ID_SIZE: usize = 32;
pub const ROUTE_TAG_SIZE: usize = 16;
pub const AEAD_KEY_SIZE: usize = 32;
pub const AEAD_NONCE_SIZE: usize = 12;

pub const MAX_SKIP: usize = 256;
pub const REPLAY_WINDOW_WIDTH: usize = MAX_SKIP + 1; // 257
pub const MAX_GOVERNANCE_SIGNERS: usize = 16;
pub const MAX_COMMIT_SIGNATURES: usize = 17; // governance plus one actor
pub const MAX_INTERACTIVE_MEMBERS: usize = 256;
pub const MAX_BROADCAST_MEMBERS: usize = 8_192;
pub const MAX_BROADCAST_PRESENTERS: usize = 16;
pub const MAX_LITE_MEMBERS: usize = 64;

const _: () = assert!(LITE_MAX_CONTENT_SIZE
    == LITE_ENVELOPE_SIZE - OUTER_HEADER_SIZE - AEAD_TAG_SIZE - INNER_HEADER_SIZE);
const _: () = assert!(STANDARD_MAX_CONTENT_SIZE
    == STANDARD_ENVELOPE_SIZE - OUTER_HEADER_SIZE - AEAD_TAG_SIZE - INNER_HEADER_SIZE);
const _: () = assert!(FULL_MAX_CONTENT_SIZE
    == FULL_ENVELOPE_SIZE - OUTER_HEADER_SIZE - AEAD_TAG_SIZE - INNER_HEADER_SIZE);
```

Any backend size mismatch is a fatal suite mismatch.

## 2. Secret wrappers

Secret-bearing types do not implement `Clone`, `Copy`, `Display`, `Serialize`,
or `Deserialize`. They either omit `Debug` or implement only the constant
redacted representation below. Their fields are private.

```rust
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[repr(transparent)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub(crate) fn expose_for_backend(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}

pub type HandshakeSecret = SecretBytes<32>;
pub type RefreshRoot = SecretBytes<32>;
pub type ChainKey = SecretBytes<32>;
pub type MessageKey = SecretBytes<32>;
pub type AeadKey = SecretBytes<32>;
pub type ConfirmKey = SecretBytes<32>;
pub type X25519Secret = SecretBytes<32>;
pub type MlKemSharedSecret = SecretBytes<32>;

// Opaque backend/HSM handles. Their private encodings are not protocol
// constants and need not be exportable.
pub struct MlKemDecapsulationKey(backend::SecretKeyHandle);
pub struct MlDsaSigningKey(backend::SecretKeyHandle);
```

The redacted `Debug` implementation is optional; omitting `Debug` entirely is
preferred for production secret types.

## 3. Envelope types

```rust
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeClass {
    Lite = 0x01,
    Standard = 0x02,
    Full = 0x03,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OuterMode {
    BootstrapInit = 0x01,
    BootstrapResp = 0x02,
    Protected = 0x03,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    HandshakeFinish = 0x01,
    Data = 0x02,
    RefreshInit = 0x03,
    RefreshResp = 0x04,
    RefreshFinish = 0x05,
    Close = 0x06,
    GroupCommit = 0x10,
    GroupWelcome = 0x11,
    GroupData = 0x12,
    IdentityRotation = 0x20,
    DeviceRevocation = 0x21,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OuterHeader {
    pub mode: OuterMode,
    pub envelope_class: EnvelopeClass,
    pub suite_id: [u8; 16],
    pub route_tag: [u8; 16],
    pub counter: u64,
}

pub struct ProtectedRecord {
    pub content_kind: ContentKind,
    pub inner_flags: u8,
    pub session_or_group_id: [u8; 32],
    pub sender_id: [u8; 32],
    pub epoch: u64,
    pub state_version: u64,
    pub message_index: u64,
    content: zeroize::Zeroizing<Vec<u8>>,
}

pub struct Envelope {
    pub class: EnvelopeClass,
    bytes: Box<[u8]>, // exact class length validated
}
```

`Envelope` is immutable after successful construction. Bootstrap and protected
parsers return validated typed views or owned zeroizing buffers, never
partially trusted field structs.

## 4. Handshake types

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum SessionPhase {
    New,
    InitSent,
    InitVerified,
    RespSent,
    RespVerified,
    FinishSent,
    FinishVerified,
    Established,
    Refreshing,
    Closing,
    Closed,
}

#[derive(Clone)]
pub struct IdentityVerificationKey {
    pub bytes: [u8; ML_DSA_65_VK_SIZE],
}

pub struct ProvisionalHandshake {
    pub role: SessionRole,
    pub phase: SessionPhase,
    pub local_identity_fingerprint: [u8; 32],
    pub expected_remote_fingerprint: [u8; 32],
    pub local_x25519_secret: X25519Secret,
    pub local_x25519_public: [u8; 32],
    pub local_mlkem_dk: Option<MlKemDecapsulationKey>,
    pub local_mlkem_ek: Option<[u8; ML_KEM_768_EK_SIZE]>,
    pub remote_x25519_public: Option<[u8; 32]>,
    pub mlkem_ciphertext: Option<[u8; ML_KEM_768_CT_SIZE]>,
    pub transcript_hash: Option<[u8; TRANSCRIPT_HASH_SIZE]>,
    pub candidate_handshake_secret: Option<HandshakeSecret>,
    pub candidate_confirm_key: Option<ConfirmKey>,
}
```

`ProvisionalHandshake` is zeroized on every failure. An established
`SessionState` is created only after the phase-specific confirmation rule in
`protocol-spec.md`.

## 5. Session state

```rust
pub struct SessionState {
    pub role: SessionRole,
    pub phase: SessionPhase,
    pub session_id: [u8; 32],
    pub transcript_hash: [u8; TRANSCRIPT_HASH_SIZE],
    pub local_identity_fingerprint: [u8; 32],
    pub remote_identity_fingerprint: [u8; 32],

    refresh_root: RefreshRoot,
    sending_chain: DirectionChain,
    receiving_chain: DirectionChain,
    skipped_keys: SkippedKeyStore,
    replay: ReplayWindow,
}

pub struct DirectionChain {
    key: ChainKey,
    next_index: u64,
}

pub struct SkippedMessageKey {
    pub session_id: [u8; 32],
    pub direction: Direction,
    pub index: u64,
    key: MessageKey,
}

pub struct SkippedKeyStore {
    entries: Vec<SkippedMessageKey>,
    max_entries: usize, // initialized to MAX_SKIP and never increased remotely
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub enum Direction {
    InitiatorToResponder,
    ResponderToInitiator,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReplayWindow {
    highest_seen: Option<u64>,
    bits: [u64; 5], // 257 used positions; remaining high bits are always zero
}
```

The fifth word is not an expanded skip allowance. It exists because the
current highest authenticated index and `MAX_SKIP` preceding indices require
`MAX_SKIP + 1` replay positions. Implementations mask the unused high bits and
still reject every forward gap greater than 256 before derivation.

`SessionState` itself MUST implement `ZeroizeOnDrop` manually or through field
composition without making secret fields public. One-use AEAD message keys are
the sole protected-record authentication keys.

## 6. Transaction types

Derivation does not mutate persistent state:

```rust
pub struct RatchetCandidate {
    pub index: u64,
    message_key: MessageKey,
    next_chain_key: ChainKey,
    aead_key: AeadKey,
    pub route_tag: [u8; 16],
}

pub struct ReceiveTransaction<'a> {
    session: &'a mut SessionState,
    provisional_chain: DirectionChain,
    provisional_skipped: SkippedKeyStore,
    provisional_replay: ReplayWindow,
    committed: bool,
}
```

Dropping an uncommitted transaction zeroizes its provisional secrets and
leaves `SessionState` unchanged. `commit()` is callable only after AEAD,
plaintext/padding, state-binding, replay, and required signature checks pass.

The reference send API eagerly installs the next chain state immediately
before returning a complete immutable envelope. Returning the envelope is its
transport-handoff boundary: cancellation or ambiguous delivery after return
still consumes the index, and retry is permitted only with those identical
returned bytes. This conservative ordering may lose a message on cancellation
but cannot reuse the fixed nonce with the same AEAD key.

## 7. Group state

```rust
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMode {
    Interactive = 0x01,
    Broadcast = 0x02,
    Lite = 0x03,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupRole {
    Member = 0x01,
    Presenter = 0x02,
    Moderator = 0x03,
    Audience = 0x04,
}

#[derive(Clone)]
pub struct GroupMember {
    pub member_id: [u8; 32],
    pub identity_fingerprint: [u8; 32],
    pub role: GroupRole,
    pub status: MemberStatus,
    pub tree_leaf_slot: u32, // 0xffffffff for an active Lite member
    pub joined_epoch: u64,
    pub removed_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    Removed,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupCommitKind {
    Create = 0x01,
    Join = 0x02,
    Leave = 0x03,
    RemoveOrRevoke = 0x04,
    GovernanceChange = 0x05,
    IdentityRotate = 0x06,
    RoleChange = 0x07,
    ModeChange = 0x08,
    TreeSelfUpdate = 0x09,
}

#[derive(Clone)]
pub struct GovernancePolicy {
    pub threshold: u8,
    pub authorized_member_ids: Vec<[u8; 32]>, // canonical, 1..=16
}

pub struct GroupSenderChain {
    pub member_id: [u8; 32],
    chain: DirectionChain,
    skipped: GroupSkippedKeyStore,
    replay: GroupReplayWindow,
}

#[derive(Clone)]
pub struct GroupModePolicy {
    pub mode: GroupMode,
    pub minimum_envelope_class: EnvelopeClass,
    pub max_active_senders: u16,
    pub per_sender_skip_bound: u16,
    pub content_policy_flags: u16,
    pub max_application_object_bytes: u32,
}

pub enum MembershipPrivateState {
    TreeKem(TreeKemPrivatePath),
    DirectWrap,
}

pub struct TreeKemPrivatePath {
    pub leaf_index: u32,
    path_secrets: Vec<SecretBytes<32>>,
    node_decapsulation_keys: Vec<MlKemDecapsulationKey>,
}

#[derive(Clone)]
pub struct GroupPublicTree {
    pub leaf_capacity: u32,
    pub tree_hash: [u8; 64],
    pub nodes: Vec<GroupPublicTreeNode>,
}

#[derive(Clone)]
pub struct GroupPublicTreeNode {
    pub node_index: u32,
    pub is_blank: bool,
    pub encapsulation_key: Option<[u8; ML_KEM_768_EK_SIZE]>,
}

pub struct GroupState {
    pub group_id: [u8; 32],
    pub mode: GroupMode,
    pub mode_policy: GroupModePolicy,
    pub epoch: u64,
    pub state_version: u64,
    pub last_commit_hash: [u8; 64],
    pub roster_hash: [u8; 64],
    pub tree_hash: [u8; 64],
    pub governance_policy: GovernancePolicy,
    pub members: Vec<GroupMember>, // canonical order, mode-bounded
    pub public_tree: Option<GroupPublicTree>,
    membership_private_state: MembershipPrivateState,
    sender_chains: Vec<GroupSenderChain>,
    pub phase: GroupPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupPhase {
    Active,
    AwaitingTransition,
    Forked,
    Closed,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GroupReplayWindow {
    highest_seen: Option<u64>,
    bits: Vec<u64>, // fixed after mode-bound validation
}
```

`epoch_secret`, `tree_root_secret`, and `epoch_prk` are setup temporaries, not
fields of `GroupState`. Installation derives required sender chains and erases
all setup secrets.

## 8. Identity lifecycle types

```rust
pub struct DeviceRevocationRecord {
    pub user_id: [u8; 32],
    pub device_id: [u8; 32],
    pub roster_version: u64,
    pub effective_epoch: u64,
    pub reason_code: u16,
    pub signatures: Vec<DeviceRevocationSignature>, // policy-bounded
}

pub struct DeviceRevocationSignature {
    pub signer_fingerprint: [u8; 32],
    pub signature: [u8; ML_DSA_65_SIG_SIZE],
}

pub struct IdentityRotationRecord {
    pub old_fingerprint: [u8; 32],
    pub new_verification_key: IdentityVerificationKey,
    pub rotation_index: u64,
    pub valid_after_epoch: u64,
    pub nonce: [u8; 32],
    pub old_signature: [u8; ML_DSA_65_SIG_SIZE],
    pub new_signature: [u8; ML_DSA_65_SIG_SIZE],
}
```

These signatures live inside protected content when a session exists. Their
canonical signing digests are defined in `protocol-spec.md`.

## 9. Errors and visibility

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HydraError {
    InvalidEnvelopeSize,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    InvalidMode,
    NonZeroReserved,
    NonCanonicalEncoding,
    ContentTooLarge,
    InvalidPadding,
    TrustRejected,
    AuthenticationFailed,
    ReplayRejected,
    StateMismatch,
    InvalidTransition,
    ResourceLimit,
    CounterExhausted,
    ForkDetected,
    CryptoFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureVisibility {
    LocalDiagnostic,
    GenericRemoteFailure,
}
```

Remote-controlled failures map to `GenericRemoteFailure`; details remain local
and rate-limited. Error values never embed attacker-controlled buffers,
plaintext, keys, signatures, or backend secret diagnostics.

Every error before a transaction commit preserves:

```text
refresh-root and direction chain keys
send/receive indices
skipped-key stores
replay windows
group epoch/roster/commit hash
application delivery state
```

## 10. Compile-time and test requirements

The implementation MUST include compile-time size assertions, exhaustive enum
decoding, property tests for checked offsets, and compile-fail tests proving
that secret types cannot be cloned or serialized. Test-only secret exposure
helpers MUST be behind `cfg(test)` and absent from release artifacts.
