# HYDRA-MSG persistence and rollback profile

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

HYDRA defines no persistence for live sessions, sender chains, skipped keys,
group traffic keys, or TreeKEM private paths.

## 1. Persisted public/control state

Implementations may persist:

```text
accepted device fingerprints and trust decisions
identity public metadata and protected identity-key handle
monotonic identity rotation/revocation policy versions
group ID, mode, policy, canonical roster, public tree
last accepted group commit hash, epoch, and state version
application ciphertext and delivery metadata
```

Group public/control state is authenticated but rollback-sensitive.

## 2. Never persisted

```text
handshake/refresh secrets
refresh roots
direction/group chain or message keys
skipped keys and replay candidate keys
group epoch/root secrets
TreeKEM path secrets or node decapsulation keys
AEAD/plaintext/scratch buffers
deterministic vector RNG state in production
```

## 3. Atomic public-state record

The persisted group record binds:

```text
storage_format = 1
group_id
group_mode
epoch
state_version
last_commit_hash
roster_hash
tree_hash
public_state_hash[64]
```

```text
public_state_hash = SHA3-512(
  "HYDRA-MSG/v1/storage/public-state-hash" || suite_id ||
  LP(canonical persisted public state excluding public_state_hash)
)
```

Writes use create-new temporary storage, complete write, file sync, atomic
rename, and parent-directory sync where supported. Parsing applies the same
canonical and resource bounds as network input.

## 4. Rollback detection

At least one non-rollbackable authority must bind the greatest accepted
rotation/revocation version and group `(epoch, state_version, commit_hash)`:
hardware monotonic storage, an authenticated transparency/account service, or
explicit revalidation with trusted peers. A local file alone is insufficient.

If freshness cannot be established after restart, the implementation:

1. sends no application data under restored state;
2. rejects delivery from uncertain group state;
3. performs a new authenticated 1:1 handshake;
4. obtains and validates current group public state plus a fresh welcome; and
5. resumes only after installing a fresh epoch.

## 5. Backup and restore

Backups may contain encrypted identity-key material and public/control state,
but never live traffic state. Restore is treated as rollback-uncertain and
follows Section 4. Cloning one device backup does not create two valid devices;
one clone must receive a new independently trusted device identity.

## 6. Crash semantics

A crash may lose undelivered messages and reserved send indices. It must not
cause key/nonce reuse because no live chain is restored. Pending partial
fragments and provisional commits are discarded.
