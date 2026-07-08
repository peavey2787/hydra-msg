# HYDRA-MSG group state and epoch commits

## Navigation

- [Main README](../../README.md)
- [Spec docs](README.md)
- [Protocol spec](protocol-spec.md)
- [Threat model](threat-model.md)
- [Public developer API](public-developer-api.md)
- [How HYDRA messaging works](../impl/message-flow/README.md)

This document defines common group roster, governance, commit, sender-chain,
replay, and epoch rules. Mode-specific behavior is normative in
`group-modes.md`; Interactive/Broadcast membership keys are defined in
`tree-kem.md`.

## 1. Group state

```text
group_id[32]
group_mode:u8
mode_policy[12]
membership_mechanism:u8
epoch:u64
state_version:u64
last_commit_hash[64]
roster_hash[64]
tree_hash[64]              // zero for DIRECT_WRAP
governance_policy
canonical roster
membership private state
authorized sender chains
per-sender replay/skipped-key state
group phase
```

Membership mechanism:

```text
0x01 TREE_KEM     // Interactive and Broadcast
0x02 DIRECT_WRAP // Lite
```

Mode/mechanism mismatches are fatal.

Limits are fixed by mode:

```text
Interactive  roster <= 256,  TreeKEM
Broadcast    roster <= 8192, TreeKEM, presenters/moderators <= 16
Lite         roster <= 64,   direct pairwise wraps
```

The roster bound includes removed entries retained for archival signature
verification. A group that exhausts its mode bound creates a successor group.

## 2. Canonical roster

Roster entry:

```text
member_id[32]
device_identity_fingerprint[32]
role:u8
status:u8 (1 = active, 2 = removed)
tree_leaf_slot:u32
joined_epoch:u64
removed_epoch:u64 (zero while active)
```

Each entry is 86 bytes. `tree_leaf_slot` is a zero-based stable slot for an
active Interactive/Broadcast member and `0xffffffff` for an active Lite
member. Active TreeKEM slots are unique and mode-bounded. Removed entries
retain their last slot for archival verification; only active entries reserve
a slot.

Roster encoding:

```text
u16(entry_count) || entries ordered lexicographically by member_id
```

Duplicate member IDs or active identity fingerprints are rejected. Active
entries require `removed_epoch = 0`; removed entries require
`removed_epoch >= joined_epoch`. Roles must be valid for `group_mode`.

Verification keys are resolved through the authenticated device roster and
must hash to the entry fingerprint.

```text
member_id = SHA3-256(
  "HYDRA-MSG/v1/group/member-id" || suite_id ||
  group_id || device_identity_fingerprint || u64(joined_epoch)
)

roster_hash = SHA3-512(
  "HYDRA-MSG/v1/group/roster-hash" || suite_id ||
  LP(canonical roster)
)
```

## 3. Governance policy

Canonical governance policy:

```text
u8(policy_version = 1) ||
u8(threshold, 1..16) ||
u8(authorized_signer_count, 1..16) ||
u8(reserved = 0) ||
authorized_member_ids[authorized_signer_count][32]
```

Authorized IDs are unique and strictly ordered. A signer is valid only if
active and authorized in the parent state.

```text
governance_policy_hash = SHA3-512(
  "HYDRA-MSG/v1/group/policy-hash" || suite_id ||
  LP(new_governance_policy)
)
```

## 4. Commit kinds

```text
0x01 CREATE
0x02 JOIN
0x03 LEAVE
0x04 REMOVE_OR_REVOKE
0x05 GOVERNANCE_CHANGE
0x06 IDENTITY_ROTATE
0x07 ROLE_CHANGE
0x08 MODE_CHANGE
0x09 TREE_SELF_UPDATE
```

One commit contains one semantic change:

```text
CREATE:
  LP(new_governance_policy) || LP(new_mode_policy)

JOIN:
  new roster entry[86]

LEAVE:
  member_id[32]

REMOVE_OR_REVOKE:
  member_id[32] || u16(reason_code)

GOVERNANCE_CHANGE:
  LP(new_governance_policy)

IDENTITY_ROTATE:
  old_member_id[32] || new roster entry[86] || rotation_digest[64]

ROLE_CHANGE:
  member_id[32] || old_role:u8 || new_role:u8

MODE_CHANGE:
  old_mode:u8 || new_mode:u8 || LP(new_mode_policy)

TREE_SELF_UPDATE:
  committer_member_id[32]
```

`TREE_SELF_UPDATE` is valid only in Interactive/Broadcast and does not alter
the roster.

## 5. Canonical commit core

```text
COMMIT_CORE =
  u8(commit_kind) ||
  group_id[32] ||
  old_group_mode:u8 || new_group_mode:u8 ||
  new_membership_mechanism:u8 ||
  u64(old_epoch) || u64(new_epoch) ||
  u64(old_state_version) || u64(new_state_version) ||
  parent_commit_hash[64] ||
  old_roster_hash[64] || new_roster_hash[64] ||
  old_tree_hash[64] || new_tree_hash[64] ||
  commit_nonce[32] ||
  change_payload_hash[64] ||
  key_schedule_commitment[64] ||
  governance_policy_hash[64] ||
  mode_policy_hash[64]
```

```text
change_payload_hash = SHA3-512(
  "HYDRA-MSG/v1/group/change-hash" || suite_id ||
  LP(CHANGE_PAYLOAD)
)

mode_policy_hash = SHA3-512(
  "HYDRA-MSG/v1/group/mode-policy-hash" || suite_id ||
  LP(new_mode_policy)
)
```

For a non-mode/policy commit, the new bytes equal the parent bytes. For direct
wrap:

```text
key_schedule_commitment = SHA3-512(
  "HYDRA-MSG/v1/group/epoch-secret-commitment" || suite_id ||
  group_id || new_group_mode || u64(new_epoch) ||
  commit_nonce || epoch_secret[32]
)
new_tree_hash = 64 zero bytes
```

For TreeKEM:

```text
key_schedule_commitment = SHA3-512(
  "HYDRA-MSG/v1/group/tree/commitment" || suite_id ||
  group_id || new_group_mode || u64(new_epoch) ||
  new_tree_hash || update_path_hash
)
```

`update_path_hash` is the domain-separated value in `tree-kem.md`.
`commit_nonce` is a fresh 32-byte OS-CSPRNG value for every proposed core.
Receivers reject a repeated nonce under the same group and parent commit.

The TreeKEM confirmation tag is separate because it requires the candidate root
secret.

## 6. Commit signatures and identity

```text
commit_sig_digest = SHA3-512(
  "HYDRA-MSG/v1/group/commit-signature" || suite_id ||
  LP(COMMIT_CORE)
)
```

Canonical signature set:

```text
u8(signature_count) ||
(signer_member_id[32] || signature[3309]) * signature_count
```

Entries are unique, strictly ordered, and count 1..17. For ordinary commits,
every signer is policy-authorized. The number of valid parent-policy signers
must meet the parent threshold.

`LEAVE` additionally requires a valid signature by the departing active
member. `TREE_SELF_UPDATE` additionally requires a valid signature by the
named active committer. If that actor is policy-authorized, one signature
satisfies both the actor and governance requirements; otherwise that one actor
entry is the only permitted non-policy signer. Creation requires exactly the
application-trusted creator signature.

```text
commit_hash = SHA3-512(
  "HYDRA-MSG/v1/group/commit-hash" || suite_id ||
  LP(COMMIT_CORE)
)
```

Signature bytes are excluded from `commit_hash`, so randomized valid signatures
over one core cannot create artificial forks.

## 7. Commit ordering and forks

Creation:

```text
old_group_mode = 0
new_group_mode = a valid nonzero mode
old/new epoch = 0
old/new state_version = 0
parent_commit_hash = zero
old_roster_hash = zero
old_tree_hash = zero
```

For every non-creation, non-mode-change commit,
`old_group_mode = new_group_mode = parent group mode`.

Every later commit requires:

```text
new_epoch = old_epoch + 1
new_state_version = old_state_version + 1
parent_commit_hash = local last_commit_hash
all old hashes/mode/policy equal local parent state
all new fields match the canonical semantic change
```

Two different valid cores with one parent are a fork. The group enters
`Forked`, stops application delivery, and requires an application-authorized
resolution or successor group. Arrival order does not resolve a fork.

## 8. Direct-wrap distribution for Lite

The Lite committer samples a fresh independent 32-byte `epoch_secret`. It
constructs one `GROUP_WELCOME` through an authenticated 1:1 HYDRA session to
every device active in the candidate roster:

```text
LP(COMMIT_CORE)
LP(CHANGE_PAYLOAD)
LP(canonical signature set)
commit_hash[64]
LP(new_roster)
LP(new_governance_policy)
LP(new_mode_policy)
epoch_secret[32]
recipient_member_id[32]
```

Recipients verify:

- pairwise channel and exact recipient;
- parent/group/mode transition;
- governance signature threshold;
- change, roster, policy, and mode hashes;
- `key_schedule_commitment` against the received secret;
- role authorization; and
- no accepted commit already exists at the candidate epoch/state version.

The complete object uses the smallest fitting Standard or Full envelope. Lite
mode constrains ordinary GROUP_DATA, not membership control records.

The committer erases the epoch secret after immutable welcomes are constructed.
Recipients erase it after sender-chain derivation.

## 9. TreeKEM distribution

Interactive and Broadcast commits contain or fragment the canonical
`UPDATE_PATH`, public-tree delta, new tree hash, and confirmation tag specified
in `tree-kem.md`.

A joining device receives its private TreeKEM welcome through an authenticated
1:1 Standard/Full record. Existing members update from the group commit.
Removed members receive neither a welcome nor a decryptable update path.

Large public-tree snapshots and update paths use bounded authenticated commit
fragments. No tree/group state changes until the complete object verifies.

## 10. Mode and identity transitions

Mode change:

- verifies under the parent governance/mode;
- validates every candidate role under the new mode;
- when entering a TreeKEM mode, assigns active entries contiguous slots from
  zero in member-ID order; when entering Lite, sets active slots to
  `0xffffffff`;
- uses fresh membership secrets under the new mechanism;
- increments epoch/state version;
- starts all new sender chains at zero; and
- erases the complete old mechanism/sender/replay state after installation.

Identity rotation:

- verifies the dual-signed record in `protocol-spec.md`;
- atomically removes the old entry and adds the new entry/fingerprint;
- binds `rotation_digest` in `CHANGE_PAYLOAD`;
- establishes fresh membership and sender secrets; and
- retains the removed entry for archival signature verification.

## 11. Epoch and sender-chain schedule

`membership_root_secret` is:

- `epoch_secret` for DIRECT_WRAP; or
- `tree_root_secret` for TREE_KEM.

```text
epoch_prk = HKDF-Extract(
  salt = SHA3-512(
    "HYDRA-MSG/v1/group/epoch" || suite_id ||
    group_id || group_mode || mode_policy_hash ||
    u64(epoch) || u64(state_version) || commit_hash
  ),
  IKM = membership_root_secret
)
```

For each active role authorized to send:

```text
sender_chain_0[S] = HKDF-Expand(
  epoch_prk,
  LP("HYDRA-MSG/v1/group/chain") ||
  LP(group_id || group_mode || mode_policy_hash ||
     u64(epoch) || u64(state_version) ||
     roster_hash || member_id[S]),
  32
)
```

Erase `epoch_prk` and `membership_root_secret` after deriving required sender
chains. Broadcast audience implementations retain only presenter/moderator
receive chains and no audience send chain. Because a malicious member can
derive or retain traffic material during setup, the ML-DSA sender signature,
not symmetric-chain possession, is the authoritative role check.

Per-message chain context:

```text
group_message_context =
  group_id || group_mode || mode_policy_hash ||
  u64(epoch) || u64(state_version) ||
  roster_hash || sender_member_id || u64(message_index)

group_message_key = HKDF-Expand(
  sender_chain[message_index],
  LP("HYDRA-MSG/v1/message-key") || LP(group_message_context),
  32
)

next_sender_chain = HKDF-Expand(
  sender_chain[message_index],
  LP("HYDRA-MSG/v1/chain-advance") || LP(group_message_context),
  32
)

group_aead_key = HKDF-Expand(
  group_message_key,
  LP("HYDRA-MSG/v1/aead-key") || LP(group_message_context),
  32
)

group_aead_nonce = 12 zero bytes
```

These values follow the same one-use, atomic send/receive, skipped-key, and
erasure rules as 1:1 chains. At `u64::MAX`, that sender stops until an
authorized fresh epoch installs new chains.

## 12. Group data authentication

```text
content_hash = SHA3-512(
  "HYDRA-MSG/v1/group/content-hash" || suite_id ||
  LP(application_content)
)

group_sig_digest = SHA3-512(
  "HYDRA-MSG/v1/group/message-signature" || suite_id ||
  group_id || group_mode || mode_policy_hash ||
  u64(epoch) || u64(state_version) ||
  roster_hash || sender_member_id || u64(message_index) ||
  envelope_class || content_hash
)
```

```text
GROUP_DATA content =
  u32(application_content_length) ||
  application_content ||
  sender_signature[3309]
```

The signature binds envelope class to prevent rewrapping one signed object into
another public size class. Receive order:

1. Select bounded candidate group/sender key by route tag/counter.
2. Authenticate/decrypt AEAD into provisional storage.
3. Validate group mode, policy, role, epoch/state, class, content, and padding.
4. Verify the required ML-DSA sender signature.
5. Apply per-sender replay checks.
6. Atomically commit chain/replay state and deliver.

Every active member can produce AEAD-valid group ciphertext because group
traffic secrets are shared. The ML-DSA signature supplies insider-resistant
sender attribution.

## 13. Routing and replay

```text
route_tag = HMAC-SHA3-256(
  group_message_key,
  "HYDRA-MSG/v1/route-tag" ||
  group_id || group_mode || u64(epoch) ||
  sender_member_id || u64(message_index)
)[0..16]
```

Replay/skipped state is keyed by:

```text
(group_id, group_mode, epoch, state_version, sender_member_id)
```

Bounds come from `group-modes.md`. Epoch/mode transition erases all parent
sender chains, skipped keys, route candidates, and replay windows after atomic
installation. The default old-epoch decrypt grace period is zero.

## 14. Join, leave, removal, and compromise

Join:

- authenticate the device fingerprint/role and group trust anchor;
- add the entry canonically;
- generate fresh membership secrets;
- give the joiner no prior membership/sender-chain secret.

Leave/removal/revocation:

- mark the entry removed;
- exclude it from direct welcomes or TreeKEM resolution;
- generate fresh membership secrets;
- reject later group data naming the removed member.

After suspected compromise, remove the device or perform a clean TreeKEM
self-update as appropriate. Future secrecy resumes only after the attacker
loses endpoint/identity access, fresh secrets install, and exposed state is
erased.

## 15. Storage and cost

| State/work | Interactive | Broadcast | Lite |
|---|---:|---:|---:|
| Public roster | O(n) | O(n) | O(n), `n <= 64` |
| Public membership tree | O(n) | O(n) | none |
| Private membership state | O(log n) | O(log n) | O(1) active setup secret |
| Sender receive chains | O(n) | O(p), `p <= 16` | O(n), `n <= 64` |
| Membership update | TreeKEM path | TreeKEM path | O(n) pairwise wraps |
| Ordinary send | AEAD + ML-DSA | presenter AEAD + ML-DSA | AEAD + ML-DSA |

Public-tree snapshot synchronization may require O(n) bytes. Balanced dense
TreeKEM cryptographic path work is normally O(log n); exact/worst-case
resolution bounds are in `tree-kem.md`.
