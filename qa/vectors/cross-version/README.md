# HYDRA-MSG cross-version compatibility vectors

## Navigation

- [Main README](../../README.md)
- [Validation docs](../../../docs/validation/gates/test-vectors.md)

These fixtures are stable compatibility artifacts for upgrade tests that live under `qa/tests/cross-version-compat/`.

`TV-COMPAT-UNKNOWN-FUTURE-SNAPSHOT-000` is an authenticated encrypted state and backup whose plaintext snapshot contains an unknown future record. The current spec rejects unknown snapshot record kinds until a migration explicitly defines them.
