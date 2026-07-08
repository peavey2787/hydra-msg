# hydra-group SRP baseline map

Status: P0 baseline and guardrails for the `hydra-group` SRP size roadmap.

Purpose: record the current ownership map before source movement begins. This file is assistant working material under `docs/project/audit/`; the active plan remains `docs/roadmap.md`.

## Baseline line counts

```text
crates/hydra-group/src/commit.rs      1123 lines
crates/hydra-group/src/state.rs       1003 lines
crates/hydra-group/src/canonical.rs    858 lines
```

Practical size target for the planned split: most new Rust files should stay under 400 lines. If a cohesive module must exceed that target, the reason must be recorded in `docs/roadmap.md` progress notes before the phase is marked complete.

## Public export baseline

`crates/hydra-group/src/lib.rs` currently exposes these modules:

```text
canonical
commit
distribution
epoch
error
membership
message
private_path
public_tree
rekey
state
types
validation
```

The SRP roadmap must preserve the public exports below unless a safe public API adjustment is explicitly recorded before the change.

### `canonical` exports

```text
change_payload_hash
checked_u16_be
checked_u32_be
commit_confirmation_tag
commit_hash
commit_sig_digest
direct_wrap_key_schedule_commitment
encode_change_payload
encode_commit_core
encode_governance_policy
encode_mode_policy
encode_roster
encode_roster_entry
encode_signature_set
governance_policy_hash
lp
member_id
mode_policy_hash
roster_hash
treekem_key_schedule_commitment
u16_be
u32_be
u64_be
validate_governance_policy
validate_roster_for_canonical_encoding
validate_signature_set
verify_commit_confirmation_tag
ChangePayload
CommitCore
CommitSignature
COMMIT_CORE_SIZE
MODE_POLICY_SIZE
ROSTER_ENTRY_SIZE
```

### `commit` exports

```text
apply_prepared_commit
install_prepared_commit
prepare_commit
validate_governance_signatures
CommitChange
CommitInstallResult
CommitPlan
PreparedCommit
```

### `state` exports

```text
AcceptedGroupMessage
GroupReplayState
GroupReplayStateSnapshot
GroupState
GroupStateConfig
GroupStateSnapshot
MembershipPrivateState
MembershipPrivateStateSnapshot
PrivatePathNodeSecretSnapshot
SenderChainCursor
SenderChainCursorSnapshot
SenderChainState
SenderChainStateSnapshot
SenderReplayState
SenderReplayStateSnapshot
SkippedGroupMessageKeySnapshot
```

## `canonical.rs` ownership map

| Current item | Target module | Responsibility |
| --- | --- | --- |
| `ROSTER_ENTRY_SIZE` | `canonical/roster.rs` | roster-entry encoded size |
| `MODE_POLICY_SIZE` | `canonical/governance.rs` | mode-policy encoded size |
| `COMMIT_CORE_SIZE` | `canonical/commit_core.rs` | commit-core encoded size |
| `u16_be` | `canonical/primitives.rs` | integer encoding |
| `u32_be` | `canonical/primitives.rs` | integer encoding |
| `u64_be` | `canonical/primitives.rs` | integer encoding |
| `checked_u16_be` | `canonical/primitives.rs` | checked integer encoding |
| `checked_u32_be` | `canonical/primitives.rs` | checked integer encoding |
| `lp` | `canonical/primitives.rs` | length-prefixed byte encoding |
| `encode_mode_policy` | `canonical/governance.rs` | mode-policy canonical encoding |
| `encode_roster_entry` | `canonical/roster.rs` | roster-entry canonical encoding |
| `encode_roster` | `canonical/roster.rs` | sorted roster canonical encoding |
| `validate_roster_for_canonical_encoding` | `canonical/roster.rs` | roster canonical validation |
| `encode_governance_policy` | `canonical/governance.rs` | governance-policy canonical encoding |
| `validate_governance_policy` | `canonical/governance.rs` | governance-policy canonical validation |
| `CommitSignature` | `canonical/signatures.rs` | commit-signature data shape |
| `encode_signature_set` | `canonical/signatures.rs` | signature-set canonical encoding |
| `validate_signature_set` | `canonical/signatures.rs` | signature-set canonical validation |
| `ChangePayload` | `canonical/changes.rs` | commit-change payload enum |
| `ChangePayload::kind` | `canonical/changes.rs` | change-kind lookup |
| `encode_change_payload` | `canonical/changes.rs` | change-payload canonical encoding |
| `CommitCore` | `canonical/commit_core.rs` | commit-core data shape |
| `encode_commit_core` | `canonical/commit_core.rs` | commit-core canonical encoding |
| `member_id` | `canonical/hashes.rs` | identity-to-member hash helper |
| `roster_hash` | `canonical/hashes.rs` | roster hash helper |
| `governance_policy_hash` | `canonical/hashes.rs` | governance-policy hash helper |
| `mode_policy_hash` | `canonical/hashes.rs` | mode-policy hash helper |
| `change_payload_hash` | `canonical/hashes.rs` | change-payload hash helper |
| `direct_wrap_key_schedule_commitment` | `canonical/hashes.rs` | direct-wrap key-schedule commitment |
| `treekem_key_schedule_commitment` | `canonical/hashes.rs` | TreeKEM key-schedule commitment |
| `commit_sig_digest` | `canonical/hashes.rs` | commit-signature digest helper |
| `commit_hash` | `canonical/hashes.rs` | commit hash helper |
| `commit_confirmation_tag` | `canonical/hashes.rs` | commit confirmation tag helper |
| `verify_commit_confirmation_tag` | `canonical/hashes.rs` | commit confirmation tag verification |
| `hash512_lp` | `canonical/hashes.rs` | private domain-separated hash helper |
| `is_strictly_ordered_member_ids` | `canonical/primitives.rs` | shared ordered-member-id helper |

`canonical/mod.rs` should hold only module declarations and public re-exports needed to preserve `crate::canonical::*` and `lib.rs` behavior.

## `state.rs` ownership map

| Current item | Target module | Responsibility |
| --- | --- | --- |
| `PrivatePathNodeSecretSnapshot` | `state/membership_private.rs` | private path node snapshot shape |
| `MembershipPrivateStateSnapshot` | `state/membership_private.rs` | private membership snapshot shape |
| `MembershipPrivateState` | `state/membership_private.rs` | private membership state |
| `MembershipPrivateState` methods | `state/membership_private.rs` | snapshot import/export, accessors, clearing |
| `MembershipPrivateState::drop` | `state/membership_private.rs` | private material clearing |
| `SenderChainCursorSnapshot` | `state/sender_chain.rs` | sender cursor snapshot shape |
| `SkippedGroupMessageKeySnapshot` | `state/sender_chain.rs` | skipped message-key snapshot shape |
| `SenderChainStateSnapshot` | `state/sender_chain.rs` | sender-chain snapshot shape |
| `SenderChainCursor` | `state/sender_chain.rs` | per-sender chain cursor |
| `SenderChainCursor` methods | `state/sender_chain.rs` | cursor construction and snapshot export |
| `SenderChainCursor::drop` | `state/sender_chain.rs` | cursor key clearing |
| `SkippedGroupMessageKey` | `state/sender_chain.rs` | skipped message-key storage |
| `SkippedGroupMessageKey` methods | `state/sender_chain.rs` | skipped key construction and snapshot export |
| `SkippedGroupMessageKey::drop` | `state/sender_chain.rs` | skipped key clearing |
| `SenderChainResolution` | `state/sender_chain.rs` | resolved sender-message step result |
| `SenderChainResolution` methods | `state/sender_chain.rs` | resolution accessors |
| `SenderChainState` | `state/sender_chain.rs` | sender-chain map and skipped-key map |
| `SenderChainState` methods | `state/sender_chain.rs` | install, send-step, receive-step, snapshot, clear |
| `derive_resolution_for_cursor` | `state/sender_chain.rs` | cursor resolution helper |
| `SenderChainState::drop` | `state/sender_chain.rs` | sender-chain clearing |
| `AcceptedGroupMessage` | `state/replay.rs` | accepted-message marker |
| `SenderReplayStateSnapshot` | `state/replay.rs` | per-sender replay snapshot |
| `GroupReplayStateSnapshot` | `state/replay.rs` | replay-state snapshot |
| `SenderReplayState` | `state/replay.rs` | per-sender accepted-message map |
| `GroupReplayState` | `state/replay.rs` | replay tracking by sender |
| `GroupReplayState` methods | `state/replay.rs` | replay install, checks, snapshot, clear |
| `GroupStateSnapshot` | `state/snapshot.rs` | full group-state snapshot shape |
| `GroupStateConfig` | `state/config.rs` | group-state construction input |
| `GroupState` | `state/mod.rs` | live group-state aggregate |
| `GroupState` construction methods | `state/config.rs` | `new_empty`, `new_validated`, snapshot restore support |
| `GroupState` snapshot methods | `state/snapshot.rs` | `export_snapshot`, `from_snapshot` |
| `GroupState` roster/mode methods | `state/roster_view.rs` | roster replacement, member add/remove, role changes, roster hashing |
| `GroupState` sender-chain methods | `state/sender_chain.rs` | epoch sender-chain installation and next sender steps |
| `GroupState` lifecycle methods | `state/mod.rs` | active checks, close, fork marking, epoch context |
| `GroupState::drop` | `state/mod.rs` | aggregate private material clearing |
| `route_tag_eq` | `state/replay.rs` | constant-time route-tag comparison helper |
| `map_replay_error` | `state/replay.rs` | replay-error to group-error mapping |
| `active_sender_entries` | `state/roster_view.rs` | active sender roster view helper |
| `compute_roster_hash` | `state/roster_view.rs` | roster hash support |

`state/mod.rs` should keep `GroupState` discoverable and re-export the focused state types so `lib.rs` exports remain stable.

## `commit.rs` ownership map

| Current item | Target module | Responsibility |
| --- | --- | --- |
| `CommitChange` | `commit/types.rs` | commit change input shape |
| `CommitChange::kind` | `commit/types.rs` | commit-kind lookup |
| `CommitPlan` | `commit/types.rs` | commit preparation input |
| `PreparedCommit` | `commit/types.rs` | prepared commit result and candidate state owner |
| `CommitInstallResult` | `commit/types.rs` | install outcome enum |
| `CandidateState` | `commit/types.rs` | candidate post-commit state |
| `prepare_commit` | `commit/prepare.rs` | prepare orchestration and commit-core assembly |
| `apply_prepared_commit` | `commit/apply.rs` | prepared-commit state application |
| `install_prepared_commit` | `commit/install.rs` | duplicate, fork, and apply selection |
| `verify_prepared_commit_integrity` | `commit/validation.rs` | prepared commit internal consistency |
| `validate_governance_signatures` | `commit/validation.rs` | governance signature validation |
| `validate_change_specific_signatures` | `commit/validation.rs` | change-specific signature validation |
| `validate_parent_for_change` | `commit/validation.rs` | parent and committer validation |
| `build_transition` | `commit/transition.rs` | candidate-state transition calculation |
| `next_transition_counters` | `commit/transition.rs` | epoch and state-version progression |
| `build_change_payload` | `commit/payload.rs` | canonical change-payload construction |
| `key_schedule_commitment` | `commit/key_schedule.rs` | TreeKEM/direct-wrap commitment selection |
| `mark_removed` | `commit/membership.rs` | roster removal mutation helper |
| `prune_removed_governance_signer` | `commit/membership.rs` | governance signer pruning |
| `removed_member_for_change` | `commit/membership.rs` | removed-member extraction |
| `remap_roster_slots_for_mode` | `commit/tree_update.rs` | roster slot remapping for target mode |
| `apply_update_path_to_public_tree` | `commit/tree_update.rs` | update-path public-tree application |
| `build_mode_change_public_tree` | `commit/tree_update.rs` | mode-change public-tree construction |
| `install_membership_material` | `commit/membership.rs` | membership material install after apply |

`commit/mod.rs` should be the stable module surface for callers and should re-export the same public commit types and functions currently exposed through `lib.rs`.

## Test movement map

### `canonical.rs` tests

| Test | Move with |
| --- | --- |
| `length_prefixed_and_integer_encoders_are_big_endian_and_checked` | `canonical/primitives.rs` |
| `roster_entry_encoding_is_exactly_86_bytes` | `canonical/roster.rs` |
| `canonical_roster_orders_by_member_id_and_rejects_duplicates` | `canonical/roster.rs` |
| `roster_count_boundaries_are_explicit` | `canonical/roster.rs` |
| `governance_policy_boundaries_are_enforced` | `canonical/governance.rs` |
| `signature_set_count_and_order_boundaries_are_enforced` | `canonical/signatures.rs` |
| `every_change_payload_kind_uses_the_normative_shape` | `canonical/changes.rs` |
| `hash_helpers_are_domain_separated_and_length_prefixed` | `canonical/hashes.rs` |
| `commit_core_encoding_and_hashes_are_exact_size_and_domain_separated` | `canonical/commit_core.rs` and `canonical/hashes.rs`; keep in `canonical/tests.rs` if it spans both after the split |
| `key_schedule_commitments_are_mechanism_specific` | `canonical/hashes.rs` |

### `state.rs` tests

`state.rs` currently has no local `#[test]` functions. During P2, any new or moved state-focused tests should live near the concern they validate. State behavior currently receives coverage through crate-level and commit-flow tests.

### `commit.rs` tests

| Test | Move with |
| --- | --- |
| `governance_signature_threshold_order_and_authorization_are_enforced` | `commit/validation.rs` |
| `lite_role_change_prepares_and_applies_atomically` | `commit/tests.rs` because it spans prepare and apply |
| `invalid_commit_preserves_parent_state` | `commit/apply.rs` or `commit/tests.rs` if it spans integrity and apply |
| `non_create_counter_overflow_rejects_before_state_change` | `commit/transition.rs` |
| `create_uses_epoch_and_state_version_zero` | `commit/transition.rs` |
| `install_reports_duplicate_without_mutation` | `commit/install.rs` |
| `sibling_commit_marks_group_forked_and_wipes_private_material` | `commit/install.rs` and `commit/membership.rs`; keep in `commit/tests.rs` if it spans both |
| `closed_or_forked_groups_reject_commit_installation` | `commit/install.rs` |
| `treekem_commit_requires_update_path` | `commit/key_schedule.rs` |

## Guardrails for P1 through P4

- Do not change public behavior while splitting by concern.
- Preserve the `lib.rs` public exports listed above.
- Keep moved helpers private unless they are already part of the public surface.
- Move tests with the concern when the test has one clear owner.
- Use a `tests.rs` file only when the test intentionally spans multiple focused modules.
- Prefer smaller, named modules over large mixed files.
- Avoid parallel helper implementations; one concern gets one owner.
- Run the full validation gate after each source split when working on a machine with Cargo available.

## Production status after P0

P0 does not make the code production-ready. It creates the map needed to perform the SRP split safely.

Remaining before the codebase can be called production-ready or enterprise-grade:

- P1 split `canonical.rs` by encoding family.
- P2 split `state.rs` by state responsibility.
- P3 split `commit.rs` by commit responsibility.
- P4 add file-size and ownership checks.
- P5 run final validation and review.
- Independent cryptographic/security review remains outside this source organization roadmap.
