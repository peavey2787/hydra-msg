# HYDRA-MSG changelog policy

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

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
