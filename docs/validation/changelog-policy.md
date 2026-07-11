# HYDRA-MSG changelog policy

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

HYDRA-MSG keeps a human-readable changelog for app developers and security reviewers.

## Format

Use `CHANGELOG.md` at the repository root with sections:

```text
Added
Changed
Deprecated
Removed
Fixed
Security
```

## Required entries

Every release must mention:

```text
public API changes
wire/storage/backup compatibility changes
security fixes
MSRV changes
dependency/security-relevant changes
migration notes
known limitations
```

Do not hide breaking behavior in commit history only.
