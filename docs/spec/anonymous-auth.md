# Anonymous Auth Metadata Boundary

## Navigation

- [Main README](../../README.md)
- [Spec document index](README.md)
- [Protocol spec](protocol-spec.md)
- [Threat model](threat-model.md)
- [Security proof sketch](security-proof-sketch.md)
- [State machines](state-machines.md)
- [Envelope serialization](envelope-serialization.md)
- [Chain-key evolution](chain-key-evolution.md)
- [TreeKEM profile](tree-kem.md)
- [Group modes](group-modes.md)
- [Group rekey](group-rekey.md)
- [Anonymous authorization](anonymous-authorization.md)


HYDRA anonymous auth is bearer-token based. It is replay-resistant through nullifiers, but it is not fully unlinkable.

A bearer token or its nullifier can link activity when reused, logged, or correlated by issuer/carrier timing. Apps must use fresh tokens, fresh scopes where possible, short expirations, no token reuse, no nullifier logging, and separate issuance/redemption transport where possible.

Bearer anonymous auth is not equivalent to blind credentials or ZK anonymous credentials. Stronger anonymity claims require future blind credentials, ZK nullifier proofs, unlinkable issuance/redemption, and scope-specific unlinkable nullifiers.
