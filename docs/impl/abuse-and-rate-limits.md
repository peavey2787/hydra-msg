# HYDRA-MSG abuse and resource-limit profile

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

Availability is not a cryptographic guarantee. Implementations nevertheless
must bound attacker-controlled work before allocation or public-key operations.

## 1. Protocol hard bounds

| Resource | Hard maximum |
|---|---:|
| envelope bytes | 147456 |
| 1:1 skipped keys | 256 |
| 1:1 replay-window positions | 257 (current plus 256 predecessors) |
| Interactive members / skip bound | 256 / 64 |
| Broadcast members / active senders / skip bound | 8192 / 16 / 256 |
| Lite members / skip bound | 64 / 32 |
| governance signers / commit signatures | 16 / 17 |
| attachment object bytes | 1073741824 |
| Tree path ciphertexts Interactive/Broadcast | 512 / 16384 |

Exceeding a hard bound is an authenticated generic rejection and never a
request to allocate more.

## 2. Pre-authentication controls

Per source/account/device and globally, deployments cap:

```text
open transports and partial records
bytes buffered and record assembly time
new handshakes and bootstrap signature/KEM operations
route-tag candidates and AEAD attempts
pending refreshes, welcomes, commits, and fragment sets
failed authentication attempts and diagnostic volume
```

Rate limits use token buckets with monotonic time. Exact rates are deployment
policy because network scale and NAT topology differ; every deployment must
publish finite burst, sustained, global, and memory ceilings. Absence of a
configured finite value is a startup error.

## 3. Work ordering

1. Transport framing and exact public size.
2. Magic/version/suite/class/reserved checks.
3. Fixed resource and concurrency admission.
4. Bounded route/state lookup.
5. AEAD or signature/KEM operation as required.
6. Canonical protected-object and policy validation.
7. Atomic state commit.

Trust/signature checks precede avoidable KEM work in bootstrap. Fragment
allocation follows authenticated metadata and aggregate quota admission.

## 4. Fragment defenses

Pending objects are keyed by authenticated owner/group and object/commit hash.
Implementations enforce total bytes, fragment count, per-owner/global object
count, duplicate consistency, expiration, and oldest-first eviction. Conflicting
duplicates invalidate the candidate. No partial object reaches application
code.

## 5. Expensive authenticated abuse

Authenticated peers can still consume signature, tree, storage, and bandwidth
resources. Apply account/group quotas, presenter moderation, attachment
limits, and administrative removal. Cryptographic validity is not authorization
to consume unlimited resources.

## 6. Failure privacy

Peer-visible responses do not distinguish parsing, trust, replay, signature,
KEM, AEAD, quota, or policy failure where doing so creates an oracle. Local
metrics use coarse categories and contain no peer-controlled high-cardinality
labels.
