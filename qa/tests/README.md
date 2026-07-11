# HYDRA-MSG system tests

## Navigation

- [Main README](../../README.md)
- [Parent QA workspace](../README.md)

`qa/tests/` contains non-production test crates for global/system checks that should not be intertwined with production modules. These crates may depend on public SDK crates and frozen vectors, but production crates must not depend on them.

## Crates

- `cross-version-compat/` verifies upgrade compatibility against frozen persistence and compatibility vectors.
- `interop/` verifies fixed packet/state/backup fixtures across runtime boundaries so HYDRA is not only testing fresh same-code peers.
