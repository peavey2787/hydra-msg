# HYDRA-MSG persistence vectors

## Navigation

- [Main README](../../../README.md)
- [Validation docs](../../../docs/validation/test-vectors.md)

Status: frozen persistence vectors are present for the canonical encrypted local-state and backup contract. Parser-stress vectors remain present for malformed container/snapshot rejection.

## Ownership

Persistence vectors prove the current encrypted local snapshot and backup envelopes. They belong under this folder because they are correctness fixtures, not implementation docs or AI working notes.

Vector generation uses deterministic test-only entropy. Production entropy must never be used to create frozen vectors.

## Layout

```text
qa/vectors/persistence/
  README.md
  manifest.sha3-256
  positive/
    manifest.sha3-256
    TV-PERSIST-EMPTY-000/
    TV-PERSIST-FULL-000/
  negative/
    manifest.sha3-256
    TV-PERSIST-WRONG-PASSWORD-000/
    TV-PERSIST-BAD-KDF-PARAMS-000/
    TV-PERSIST-CIPHERTEXT-FLIP-000/
    TV-PERSIST-TRUNCATED-000/
    TV-PERSIST-BAD-SNAPSHOT-000/
    TV-PERSIST-STALE-GENERATION-000/
  parser-stress/
    manifest.sha3-256
    TV-PERSISTENCE-*/
```

Each vector case stores metadata separately from raw bytes. Binary fixtures have lowercase contiguous `.hex` mirrors.

## Passwords

The frozen encrypted-state fixtures use:

```text
state password  state-pw
backup password backup-pw
wrong password  wrong-pw
```

These are test-fixture passwords only. They are not examples of production password quality.

## Positive vectors

- `TV-PERSIST-EMPTY-000`: empty encrypted state opens correctly; empty backup verifies.
- `TV-PERSIST-FULL-000`: full encrypted state opens correctly and backup verifies/imports. The decrypted snapshot contains one identity, one contact, one message with a bytes attachment, one lobby, one anonymous-auth secret, and one spent nullifier.

## Negative vectors

- `TV-PERSIST-WRONG-PASSWORD-000`: valid state and backup envelopes reject the wrong password.
- `TV-PERSIST-BAD-KDF-PARAMS-000`: changed KDF parameters are rejected.
- `TV-PERSIST-CIPHERTEXT-FLIP-000`: one ciphertext/tag mutation fails authentication.
- `TV-PERSIST-TRUNCATED-000`: truncated encrypted state fails closed.
- `TV-PERSIST-BAD-SNAPSHOT-000`: authenticated backup plaintext fails snapshot validation before mutation.
- `TV-PERSIST-STALE-GENERATION-000`: older authenticated state is rejected when local rollback evidence records a newer generation.

## Parser-stress vectors

`parser-stress/` contains malformed persistence fixtures that must be rejected before mutation:

- `TV-PERSISTENCE-STATE-BAD-MAGIC` — unsupported encrypted-state magic.
- `TV-PERSISTENCE-STATE-EMPTY-CIPHERTEXT` — encrypted-state envelope with no ciphertext bytes.
- `TV-PERSISTENCE-BACKUP-BAD-KDF` — backup envelope with unsupported KDF algorithm.
- `TV-PERSISTENCE-BACKUP-BAD-NONCE` — backup envelope with the wrong nonce length.
- `TV-PERSISTENCE-SNAPSHOT-DUPLICATE-SCALAR` — plaintext snapshot with a duplicate required scalar.

## Required runtime checks

`crates/hydra-msg/src/tests/persistence.rs` must include the frozen vectors and check:

- empty encrypted state opens correctly;
- full encrypted state opens correctly;
- backup verifies correctly;
- backup imports restore correctly;
- wrong password fails;
- ciphertext bit flip fails;
- truncated envelope fails;
- authenticated malformed snapshot fails before mutation;
- stale generation is rejected by native rollback evidence;
- restore preserves the target local generation floor.

`qa/ci/security/check-persistence-invariants.*` enforces that this fixture coverage remains wired into the codebase.
