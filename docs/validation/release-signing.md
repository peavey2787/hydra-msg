# HYDRA-MSG release signing policy

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

HYDRA production releases require signed Git tags and signed artifact checksums.

## Required tools

The current release process uses:

```text
git
gpg
sha256sum
```

Signing keys must not be stored in the repository.

## Git tags

Release tags must be annotated and signed:

```bash
scripts/release/create-signed-tag.sh vX.Y.Z [gpg-key-id]
git verify-tag vX.Y.Z
```

Unsigned release tags are not production releases.

## Artifact signatures

HYDRA signs the checksum file:

```bash
scripts/release/sign-release-artifacts.sh vX.Y.Z [gpg-key-id]
scripts/release/verify-release-artifacts.sh vX.Y.Z
```

This produces and verifies:

```text
release-artifacts/<version>/SHA256SUMS.txt
release-artifacts/<version>/SHA256SUMS.txt.asc
```

A release may additionally sign individual artifacts, but the signed checksum manifest is the required verification path.

## Signing-key policy

The release manager must document in release evidence:

```text
signing key fingerprint
who controls the key
where the public key is published
how the key is backed up
rotation policy
compromise response
```

If a signing key is compromised, revoke it, publish a security advisory, rotate the key, and reissue affected artifacts when appropriate.

## GitHub release rule

The GitHub release must be created from the signed tag. Upload only artifacts that appear in `SHA256SUMS.txt`, and upload `SHA256SUMS.txt.asc` with them.
