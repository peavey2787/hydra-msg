# HYDRA candidate vector generator

This isolated tool generates deterministic envelope and 1:1 handshake vectors
from `hydra-core`, `hydra-envelope`, and the `hydra-crypto` candidate adapter.
It also generates candidate primitive vectors from one executable RustCrypto
backend:

```text
cargo run --release --manifest-path qa/tools/vector-gen/Cargo.toml
```

Generation verifies the resulting manifest, artifact inventory, hashes, and
binary/hex mirrors. An existing output tree can be checked without rewriting
it:

```text
cargo run --release --manifest-path qa/tools/vector-gen/Cargo.toml -- --verify
```

Output is written to `qa/vectors/candidate/`. The handshake set contains
byte-complete INIT, RESP, and FINISH envelopes plus transcript, hybrid KDF,
session, and confirmation artifacts. It executes both roles' X25519/ML-KEM
agreement, signature verification, confirmation verification, and FINISH AEAD
open. These are single-backend candidate results. The incomplete bundle is not
frozen, does not establish PQ backend independence, and does not establish
full-protocol interoperability.

The tool uses the test-only entropy schedule in
`docs/validation/test-vectors.md`. Its `ml-kem` `hazmat` feature is required for
deterministic encapsulation and must never be enabled in production code.
Deterministic ML-DSA internals are likewise confined to this isolated tool;
production signing remains randomized through `hydra-crypto`.
