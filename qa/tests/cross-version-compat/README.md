# HYDRA-MSG cross-version compatibility tests

## Navigation

- [Main README](../../../README.md)
- [Parent QA workspace](../../README.md)
- [System tests](../README.md)

This QA crate verifies compatibility behavior using public HYDRA-MSG APIs and frozen fixtures. It intentionally lives outside production crates so upgrade tests do not become intertwined with production code.

Coverage:

- frozen v1 encrypted state opens in the current runtime;
- frozen v1 backup imports in the current runtime;
- unknown future snapshot records fail closed until a migration explicitly supports them;
- old rollback-generation evidence still rejects stale state;
- restoring an old backup preserves a newer local generation floor;
- fragmented packets produced through the public packet-size/send/receive contract reassemble through the public receive path.
