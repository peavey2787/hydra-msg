# HYDRA-MSG post-quantum TreeKEM profile

This document defines the membership-key mechanism used by Interactive and
Broadcast groups. It is a HYDRA-specific TreeKEM profile using ML-KEM-768,
ML-DSA-65, HKDF-HMAC-SHA3-256, SHA3-512, and ChaCha20-Poly1305.

## 1. Scope and security model

TreeKEM establishes one fresh group root secret after an authenticated tree
commit. Application messages do not use tree node keys directly. The root
secret initializes mode-specific sender chains and is erased.

Security requires:

- canonical tree shape and node indexing;
- authenticated identity/role binding for every leaf;
- a fresh unpredictable committer path secret;
- exact public-tree hash verification;
- ML-DSA-authorized commits;
- AEAD-protected KEM path-secret wraps;
- commit confirmation under the candidate root; and
- atomic state replacement and erasure.

TreeKEM does not prevent an authorized member from leaking group secrets. A
member/device compromise reveals the group epochs represented by its live tree
and sender-chain state. Recovery conditions are in Section 12.

## 2. Tree shape and indexing

The public tree is a balanced left-filled binary tree over a power-of-two leaf
capacity. Nodes use heap indexing:

```text
root index = 1
left(v) = 2 * v
right(v) = 2 * v + 1
parent(v) = floor(v / 2)
```

Leaf slots are the authenticated `tree_leaf_slot` values in the canonical
roster. Empty capacity slots are vacant. Capacity is fixed by mode:

```text
Interactive  256 leaves
Broadcast   8192 leaves
```

For zero-based leaf slot `s`, the heap node index is `leaf_capacity + s`.
Active TreeKEM roster entries have unique slots in
`0..leaf_capacity`; a join uses the lowest vacant slot. Roster sorting never
changes a slot. Mode changes build a fresh tree and may assign active members
new slots as specified in `group-rekey.md`; no ordinary commit compacts or
silently remaps them.

## 3. Public and private node state

A public node has an optional key:

```text
node_index:u32
has_encapsulation_key:u8
mlkem_encapsulation_key[1184]  // present exactly when flag is 1
```

An occupied leaf additionally binds:

```text
member_id[32]
identity_fingerprint[32]
role:u8
leaf_generation:u64
```

The leaf's `member_id`, fingerprint, and role must equal the active roster
entry naming that authenticated slot.

A member stores:

- the public tree;
- its leaf path secret;
- derivable ML-KEM decapsulation keys on its direct leaf-to-root path; and
- no private key for a node outside that direct path.

Private node material is never placed in public tree state, logs, or
persistence.

## 4. Domain labels

Exact labels are listed centrally in `protocol-spec.md`:

```text
HYDRA-MSG/v1/group/tree/path
HYDRA-MSG/v1/group/tree/node-seed
HYDRA-MSG/v1/group/tree/node-hash
HYDRA-MSG/v1/group/tree/tree-hash
HYDRA-MSG/v1/group/tree/wrap-salt
HYDRA-MSG/v1/group/tree/wrap-key
HYDRA-MSG/v1/group/tree/confirmation
HYDRA-MSG/v1/group/tree/root
HYDRA-MSG/v1/group/tree/update-path-hash
```

## 5. Path and node derivation

The committer samples a fresh 32-byte `leaf_path_secret` from the OS CSPRNG.
For a direct-path node `v`, bottom-up:

```text
path_secret[parent(v)] = HKDF-Expand(
  path_secret[v],
  LP("HYDRA-MSG/v1/group/tree/path") ||
  LP(group_id || u64(new_epoch) || u64(new_state_version) ||
     u32(parent(v)) || commit_nonce),
  32
)
```

For each direct-path node:

```text
node_seed = HKDF-Expand(
  path_secret[v],
  LP("HYDRA-MSG/v1/group/tree/node-seed") ||
  LP(group_id || u64(new_epoch) || u32(v) || commit_nonce),
  64
)

d = node_seed[0..32]
z = node_seed[32..64]
(node_dk[v], node_ek[v]) = ML-KEM-768.KeyGen_internal(d, z)
```

`KeyGen_internal` is the deterministic seeded operation specified by FIPS 203.
Seed bytes and decapsulation keys are secret. The public 1184-byte
encapsulation key is published in the update path.

The root path secret derives:

```text
tree_root_secret = HKDF-Expand(
  path_secret[root],
  LP("HYDRA-MSG/v1/group/tree/root") ||
  LP(group_id || group_mode || u64(new_epoch) ||
     u64(new_state_version) || commit_nonce),
  32
)
```

## 6. Tree hashing

Vacant leaf hash:

```text
node_hash[v] = SHA3-512(
  "HYDRA-MSG/v1/group/tree/node-hash" || suite_id ||
  group_id || u32(v) || u8(occupied = 0)
)
```

Occupied leaf hash:

```text
node_hash[v] = SHA3-512(
  "HYDRA-MSG/v1/group/tree/node-hash" || suite_id ||
  group_id || u32(v) || u8(occupied = 1) ||
  node_ek[v] || member_id || identity_fingerprint ||
  role || u64(leaf_generation)
)
```

Every parent hash commits its children even when the parent has no key:

```text
node_hash[v] = SHA3-512(
  "HYDRA-MSG/v1/group/tree/node-hash" || suite_id ||
  group_id || u32(v) || u8(has_encapsulation_key) ||
  optional_node_ek[v] ||
  node_hash[left(v)] || node_hash[right(v)]
)
```

`optional_node_ek` is 1184 zero bytes when the flag is zero and the exact
ML-KEM key otherwise. A parent without a key is not an empty subtree; its
children remain committed and its resolution recurses into them.

```text
tree_hash = SHA3-512(
  "HYDRA-MSG/v1/group/tree/tree-hash" || suite_id ||
  group_id || u32(leaf_capacity) || node_hash[root]
)
```

Decoders recompute the complete affected path and reject any mismatch;
public-key substitution cannot preserve `tree_hash`.

## 7. Copath resolution

For each direct-path node `v` below the root, `copath(v)` is its sibling. The
base resolution of a subtree is:

- its root node if that node has a public key; otherwise
- the ordered concatenation of its children's resolutions; or
- empty for a subtree with no occupied leaves.

Removal uses an exclusion-filtered resolution. Let `excluded_nodes` be every
node on the removed leaf's direct path in the parent tree, including the leaf
and root. A candidate subtree root may appear in a resolution only if:

- it has a public key; and
- its node index is not in `excluded_nodes`.

If a candidate fails one of those tests, resolution recurses into its children
and omits any branch containing no candidate active recipient. This prevents a
removed member from using a decapsulation key learned in the parent state.
For non-removal updates, `excluded_nodes` is empty. A commit removing its own
committer leaf is invalid; an authorized remaining member must commit it.

Resolution node indices are encoded in ascending order. Duplicate,
out-of-subtree, blank, excluded, or unauthorized targets are rejected.
Recipients recompute the filtered resolution from the authenticated parent
tree and candidate roster rather than trusting target indices supplied by the
committer.

## 8. Path-secret encryption

For every `target` in `resolution(copath(v))`, the committer encapsulates:

```text
(kem_ciphertext, kem_shared_secret) =
  ML-KEM-768.Encapsulate(node_ek[target])

wrap_context =
  group_id || group_mode || u64(new_epoch) || u64(new_state_version) ||
  commit_nonce || u32(parent(v)) || u32(target) || tree_hash

wrap_prk = HKDF-Extract(
  salt = SHA3-512(
    "HYDRA-MSG/v1/group/tree/wrap-salt" || suite_id ||
    LP(wrap_context)
  ),
  IKM = kem_shared_secret
)

wrap_key = HKDF-Expand(
  wrap_prk,
  LP("HYDRA-MSG/v1/group/tree/wrap-key") || LP(wrap_context),
  32
)

wrapped_path_secret = ChaCha20-Poly1305.Seal(
  key = wrap_key,
  nonce = 12 zero bytes,
  plaintext = path_secret[parent(v)],
  aad = wrap_context || kem_ciphertext
)
```

`wrap_key` is unique because every ML-KEM encapsulation produces a fresh
shared secret and each `(parent, target, commit_nonce)` context is unique.
KEM shared secrets, wrap PRKs/keys, and plaintext path secrets are erased after
use.

Canonical path ciphertext:

```text
parent_node_index:u32
target_node_index:u32
kem_ciphertext[1088]
wrapped_path_secret[48]  // 32-byte secret + 16-byte AEAD tag
```

## 9. Update path and commit binding

Canonical `UPDATE_PATH` contains:

```text
u32(committer_leaf_index)
u32(leaf_capacity)
u16(updated_node_count)
(
  u32(node_index) ||
  u8(has_encapsulation_key) ||
  [node_ek[1184] when has_encapsulation_key = 1]
) * updated_node_count
u16(path_ciphertext_count)
(
  u32(parent_node_index) ||
  u32(target_node_index) ||
  kem_ciphertext[1088] ||
  wrapped_path_secret[48]
) * path_ciphertext_count
candidate_tree_hash[64]
```

Updated nodes are strictly increasing by index and contain exactly the
committer direct path plus any keys retired by a removal; no unchanged node
may be included. Path ciphertexts are strictly ordered by
`(parent_node_index, target_node_index)`. Counts must equal the recomputed path
and filtered resolutions, fit the Section 14 bounds, and use checked
arithmetic. Flags other than zero or one, duplicate entries, missing required
mutations, extra mutations, and trailing bytes are rejected.

The common group commit in `group-rekey.md` includes:

```text
membership_mechanism = TREE_KEM
old_tree_hash
new_tree_hash
update_path_hash[64]
```

through its key-schedule commitment. The entire commit core is authorized by
the governance-required ML-DSA signature set. Signature bytes do not alter the
canonical commit hash.

```text
update_path_hash = SHA3-512(
  "HYDRA-MSG/v1/group/tree/update-path-hash" || suite_id ||
  LP(UPDATE_PATH)
)
```

If one Full envelope cannot contain the update path/public-tree delta, the
commit is split into authenticated `GROUP_COMMIT` fragments. Every fragment
binds:

```text
commit_hash[64]
fragment_index:u32
fragment_count:u32
total_commit_bytes:u64
commit_object_hash[64]
```

```text
commit_object_hash = SHA3-512(
  "HYDRA-MSG/v1/group/commit-object-hash" || suite_id ||
  LP(canonical complete commit object)
)
```

No state is applied until all bounded fragments authenticate, reassemble
canonically, and the complete commit verifies.

## 10. Recipient processing

A non-committing existing recipient:

1. Verifies group ID/mode, parent commit, epoch/state transition, roster/role
   change, governance signatures, fragment digest, and public-tree shape.
2. Finds exactly one path ciphertext targeted to a private direct-path node.
3. Decapsulates ML-KEM and opens the 32-byte path secret with exact AAD.
4. Derives all ancestor path secrets and node keypairs to the root.
5. Recomputes affected node hashes and exact `new_tree_hash`.
6. Derives `tree_root_secret`.
7. Verifies the confirmation tag in Section 11.
8. Derives only the mode-authorized sender-chain state specified in
   `group-rekey.md`.
9. Atomically replaces tree/group state and erases all replaced/provisional
   secrets.

The committer performs the same checks but uses its locally generated path
secret instead of opening a path ciphertext. A joining recipient initializes
from the pairwise welcome and verifies the identical core, public tree, root
confirmation, and commit hash. Failure at any step preserves the complete
parent state.

## 11. Commit confirmation

```text
confirmation_key = HKDF-Expand(
  tree_root_secret,
  LP("HYDRA-MSG/v1/group/tree/confirmation") ||
  LP(group_id || group_mode || u64(new_epoch) ||
     u64(new_state_version) || new_tree_hash || commit_hash),
  32
)

confirmation_tag = HMAC-SHA3-256(
  confirmation_key,
  commit_hash || new_tree_hash
)
```

The tag is carried in the commit after `commit_hash` is known. All recipients
must reproduce it. `confirmation_key` is erased after verification.

## 12. Join, removal, and update

Join:

- assign the next canonical blank leaf;
- authenticate the joining device/role;
- update the sponsor/committer direct path with fresh secrets;
- send a pairwise protected welcome containing the joiner's leaf/path material
  and authenticated public tree snapshot/delta; and
- never send a prior root/path/sender-chain secret.

Removal:

- mark the removed leaf vacant;
- let `lca` be the least common ancestor of the removed and committer leaves;
- remove the public keys from every removed-leaf direct-path node below
  `lca`, so those parent-state keys can never be resolution targets again;
- use the exclusion-filtered resolution from Section 7;
- replace `lca` and every ancestor on the authorized remaining committer path
  with fresh keys;
- send no welcome/path secret to the removed device; and
- erase the parent epoch after atomic installation.

Self-update:

- an active member replaces its own leaf/path with fresh entropy without a
  roster change;
- increments epoch and state version; and
- is the required recovery operation after that member's tree state may have
  been exposed.

Role/presenter changes also perform a fresh tree update because they change
sender authorization and sender-chain state.

## 13. State-compromise recovery

A snapshot of one member's tree private path can expose subsequent roots that
are encrypted to keys in that compromised state. Recovery requires the
remediated member itself to perform an identity-signed self-update with fresh
leaf entropy after the attacker loses access.

Recovery does not hold if:

- the identity signing key remains compromised;
- the attacker still controls the endpoint;
- the attacker compromises enough other live tree paths to recover the new
  path; or
- the update is blocked.

After a successful clean self-update, new path/root/sender-chain secrets are
independent of the exposed leaf secret under the KDF/KEM assumptions.

## 14. Complexity and bounds

For a balanced dense tree:

```text
private tree state per member       O(log n)
public tree state per member        O(n)
direct-path public keys             O(log n)
path-secret encryptions             O(log n)
tree hashing for delta              O(log n), plus snapshot synchronization
```

Blank-node resolution can increase ciphertext count. Implementations calculate
the exact resolution before cryptography and reject a commit that exceeds:

```text
Interactive maximum path ciphertexts  512
Broadcast maximum path ciphertexts    16384
```

These are resource bounds, not expected costs. Public-tree snapshots and large
Broadcast updates may span multiple Full envelopes. Ordinary application data
never carries tree update material.
