# HYDRA-MSG external review status

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

## Current status fields

Each release evidence directory must state:

```text
external cryptography review: archived / not archived
external secure-code review: archived / not archived
independent backend/vector review: archived / not archived
findings disposition: complete / incomplete / not applicable
```

Internal tests, fuzzing, Miri, sanitizers, browser E2E, and supply-chain gates are necessary release evidence. They do not become an external review unless an independent reviewer performs and signs off on that work.

## Required review areas

A production-grade external review should cover:

```text
hybrid handshake transcript binding
cross-context domain separation
replay and counter behavior
session receive state machine
key evolution and rekey behavior
group commit/message parsing
group membership transitions
anonymous-auth nullifier/linkability policy
backup/state encryption and rollback behavior
storage chunk parser and AAD binding
browser persistence and multi-tab concurrency
native same-profile locking
resource-exhaustion fail-closed boundaries
public API misuse behavior
release artifact provenance/signing/SBOM process
```

## Finding disposition

Every finding must have one of these dispositions before an externally reviewed claim:

```text
fixed with regression test
accepted risk with release-note disclosure
not applicable with reviewer agreement
deferred and explicitly scoped in release notes
```

## Release wording

A release may accurately say internal gates passed when the logs are archived. It may accurately say externally reviewed only when review evidence is archived for that release or for an unchanged reviewed scope.
