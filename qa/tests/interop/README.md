# HYDRA-MSG interop tests

## Navigation

- [Main README](../../../README.md)
- [Parent QA workspace](../../README.md)
- [System tests](../README.md)

This QA crate verifies that HYDRA runtime code consumes stable, frozen artifacts instead of only testing two fresh instances of the same runtime talking to itself.

Coverage:

- frozen protocol packet opens and delivers the expected plaintext through the current session runtime;
- frozen envelope/header fixture remains byte-stable;
- frozen encrypted state and backup fixtures remain hash-stable and open/import in the current runtime;
- the same encrypted state bytes used by native persistence are accepted through the WASM snapshot boundary;
- pre-v1 compatibility fixtures fail closed; current fixtures define the first production candidate format.
