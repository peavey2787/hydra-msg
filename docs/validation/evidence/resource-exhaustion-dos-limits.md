# Resource-exhaustion and denial-of-service limits audit

## Navigation

- [Main README](../../../README.md)
- [Validation index](../README.md)
- [Spec document index](../../spec/README.md)
- [Threat model](../../spec/threat-model.md)

Status: implemented internal production hardening; maintainer validation and external review remain required.

## Scope

This audit covers attacker-controlled bytes and state growth in `hydra-msg`,
`hydra-session`, and `hydra-group`. The objective is not to guarantee
availability against an attacker who can saturate the carrier or repeatedly
invoke the API. The objective is to ensure each individual parser/state-machine
operation has a hard input ceiling, bounded retained state, and bounded work.

The facade limits are centralized in `crates/hydra-msg/src/limits.rs`. Session
and group limits that are protocol invariants remain in `hydra-core` or the
owning crate.

## Enforced limits

| Boundary | Hard ceiling | Enforcement point |
|---|---:|---|
| Encrypted local state | 128 MiB + 512 KiB envelope | File metadata and byte-slice checks before parse/KDF/decrypt |
| Encrypted backup | 128 MiB + 512 KiB envelope | Entry check before KDF/decrypt |
| Decrypted state snapshot | 64 MiB | Before UTF-8 parsing and while encoding |
| Identities | 256 | Mutation, import, snapshot encode/decode |
| Contacts | 1,024 | Mutation, handshake-created contact, import, snapshot encode/decode |
| Imported contact bytes | 16 MiB | Before UTF-8 parsing |
| Imported contact records | 1,024 | During atomic parse before state mutation |
| Lobbies | 256 | Mutation and snapshot encode/decode |
| Stored messages | 100,000 total; 10,000/contact | Send, receive, import, snapshot encode/decode |
| Stored message bytes | 256 MiB total; 64 MiB/contact | Send, receive, import, snapshot encode/decode |
| Message plaintext | 4 MiB | Before packing/allocation and during decode |
| Attachments | 16/message | Before packing/allocation and during decode |
| Attachment bytes | 16 MiB/attachment | File metadata before read, bounded read, constructors, decode |
| Encoded message | 32 MiB | Before parsing, fragmentation, storage accounting |
| Handshake offer/answer | 16 KiB each | Before field parsing, signature verification, KEM work |
| Pending initiator handshakes | 64; 10-minute age | Before creating additional handshake state; stale entries expired |
| Anonymous-auth token | 4 KiB | Before text/field parsing |
| Spent anonymous-auth nullifiers | 100,000 | Mutation and snapshot encode/decode; hash index for bounded lookup |
| Fragment count | 16,384/logical message | Decode and outbound split checks |
| Pending fragment parts | 16,384 global | Before retaining a new part |
| Incomplete fragmented messages | 128 global; 8/contact; 8/lobby | Before creating reassembly state |
| Pending fragment bytes | 64 MiB global | Before retaining a new part |
| Fragment age | 10 minutes | Expired before accepting additional fragment work |
| Session skipped keys | `MAX_SKIP` | Receive gap checks and snapshot restore validation |
| Session receive-route tags | `MAX_SKIP + 1`/session | Derived/indexed with a global contact-derived ceiling |
| Group skipped sender keys | Mode-specific sender skip bound | Snapshot restore and normal sender-chain logic |
| Group replay evidence | Replay-window width/sender | Runtime pruning and snapshot restore validation |
| Lobby outbound fanout | 4,096 packets; 64 MiB envelopes | Preflight before packet allocation/encryption |

## Parser and allocation findings closed

1. Fragment reassembly no longer allocates a dense vector from an untrusted
   declared fragment count. It retains only received parts in a sparse map.
2. Declared message and attachment lengths are checked before `Vec` allocation
   or copying. Trailing bytes and excess fields are rejected.
3. Native state and attachment files are opened first, checked through metadata
   on that same handle, and read through a `max + 1` bounded reader.
4. Contact and message imports parse and validate the complete candidate set
   before mutating live state.
5. Backup/state ceilings are enforced before password KDF, AEAD open, or
   snapshot parsing.
6. Incomplete fragments are ephemeral and do not force a full encrypted-state
   write for every fragment.
7. Inbound session dispatch uses the authenticated outer route tag and a bounded
   route index instead of attempting ratchet work against every active session.
8. Anonymous-auth spent-token checks use a bounded hash index rather than a
   linear scan over the retained history.
9. Group snapshot restore rejects oversized, duplicate, or unauthorized sender,
   skipped-key, replay, membership-tree, and private-path state.

## Work bounds and remaining application responsibilities

HYDRA bounds work per accepted API call. It does not own the carrier, connection
pool, HTTP body reader, WebRTC queue, mailbox, process memory limit, filesystem
quota, or request scheduler. Applications must still apply ingress byte limits
before buffering a complete carrier object, per-source and global rate limits,
connection/concurrency limits, backpressure, timeouts, and durable-storage
quotas.

Fixed-cost ML-DSA, ML-KEM, password-KDF, and AEAD operations remain intentionally
expensive. Their input sizes and operations per HYDRA call are bounded, but an
application must rate-limit repeated calls from untrusted sources. Network-level
proof of work, account reputation, CAPTCHAs, payments, and carrier abuse controls
remain outside the SDK.

## Regression evidence

The implementation includes adversarial tests for oversized handshake/auth
records, declared attachment lengths, sparse oversized files, state-file
ceilings, fragment sparsity/conflicts/age/scope quotas, skipped-key snapshot
limits, route-index refresh, no-persist partial fragments, and group
sender/replay snapshot bounds.

`qa/ci/security/check-resource-limits.sh` and
`qa/ci/security/check-resource-limits.ps1` statically guard the required constants,
enforcement paths, tests, and the removed dense-fragment/session-scan patterns.
These gates complement, but do not replace, Cargo tests, fuzzing, sanitizers,
fault injection, load testing, or external review.
