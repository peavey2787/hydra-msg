# HYDRA-MSG v1 secret-memory lifecycle

This document defines best-effort secret minimization and erasure. It does not
claim that software can guarantee physical RAM destruction: compilers,
runtimes, allocators, kernels, crash facilities, hibernation, DMA devices, and
hardware copies may retain data outside the process's control.

## 1. Threat model

The strategy reduces exposure to:

- accidental logging, formatting, serialization, and cloning;
- ordinary allocator reuse after secrets are no longer needed;
- process memory inspection after erased keys are no longer available;
- swap, core-dump, and hibernation exposure where the OS controls are
  available; and
- secret remnants in explicitly managed cryptographic scratch buffers.

It does not defeat an attacker controlling the process while keys are live,
the kernel/hypervisor, physical memory acquisition, malicious firmware,
debuggers with sufficient privilege, or compiler/backend copies outside the
managed buffer.

“Memory-hard wiping,” dilution pools, repeated random overwrite passes, and
background mutation of active keys are not v1 mechanisms. They provide no
portable cryptographic guarantee and can enlarge the secret footprint.

## 2. Core rules

1. Keep secrets in the smallest practical number of owned buffers.
2. Never derive `Clone`, `Copy`, `Serialize`, `Deserialize`, `Display`, or
   ordinary `Debug` for secret-bearing types.
3. Pass secrets by reference or move; never duplicate them for convenience.
4. Use vetted backend APIs that accept caller-owned output/scratch buffers
   when possible.
5. Zeroize secret buffers that are no longer needed with operations intended not to be optimized away.
6. Erase temporaries on every success, error, cancellation, panic boundary,
   timeout, and shutdown path.
7. Never let a background scrubber borrow or mutate active protocol state.
8. Treat page locking and dump exclusion as best-effort hardening, not
   zeroization.
9. Do not persist refresh-root, chain, message, skipped, epoch, or scratch secrets
   unless a separate encrypted crash-recovery design explicitly specifies
   rollback protection. v1 defines no such persistence.

## 3. Secret inventory and lifetime

| Secret | Maximum intended lifetime |
|---|---|
| ML-DSA-65 identity signing key | Device identity lifetime |
| Handshake ML-KEM decapsulation key | INIT through validated RESP or abort |
| Handshake X25519 private value | Handshake confirmation or abort |
| ML-KEM/X25519 shared secrets | Hybrid extract only |
| Provisional handshake/confirm/finish secrets | Handshake completion or abort |
| Refresh root | Session/refresh lifetime; cannot derive sibling chains |
| Direction chain key | Until atomic next-state commit |
| Message/AEAD key and nonce material | One envelope seal/open transaction |
| Skipped message key | Bounded gap resolution, eviction, refresh, or close |
| Group epoch secret/PRK | Sender-chain derivation during epoch installation |
| TreeKEM leaf/path/node private state | Active tree epoch or atomic replacement |
| TreeKEM root secret | Sender-chain derivation during tree installation |
| TreeKEM KEM shared/wrap key | One path-secret wrap/open operation |
| Group sender chain key | Until next accepted message for that sender/epoch |
| Plaintext protected-record buffer | One class-bounded parse/delivery transaction |
| ML-KEM/ML-DSA backend scratch | One backend call |

Public keys, ciphertexts, signatures, hashes, route tags, counters, and
transcript hashes are not secrets, though they may still be privacy-sensitive.

## 4. Secret container

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[repr(transparent)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub(crate) fn expose_for_backend(&self) -> &[u8; N] {
        &self.bytes
    }
}
```

Fields remain private to the owning crate. There is no public mutable slice,
`into_inner`, or generic byte-vector conversion. If the selected backend
forces an extra copy, the adapter owns and zeroizes that copy immediately.

Heap-backed secret buffers use a zeroizing allocation wrapper with validated
Lite/Standard/Full class capacity. Shrinking or reallocating a secret vector is
forbidden because the old allocation may retain bytes. Secret-bearing
containers are preallocated only after class and protocol bounds validate.

## 5. Active-state replacement

Active state is mutated only by the protocol transaction that owns it. When a
key advances, use move/replace semantics:

```text
derive next state in zeroizing temporary storage
authenticate and validate
atomically swap next state into the owner
move old state into a local value
zeroize and drop that local value before returning
```

Ordinary fixed-size old keys SHOULD be zeroized synchronously. A background
cleanup queue is allowed only for unusually large backend scratch
allocations and only if:

- ownership is moved, never cloned;
- queue capacity is fixed;
- overflow causes synchronous zeroization;
- the worker has no reference to live session/group state; and
- shutdown drains and wipes the queue.

Timing of secret cleanup is not exposed to remote peers.

## 6. Transaction cleanup

Send/receive/handshake/refresh/group-install transactions own all provisional
values. Their drop path erases:

```text
candidate handshake secrets, refresh roots, and chains
message and AEAD keys
ML-KEM/X25519 shared secrets
confirmation keys
unused skipped-key candidates
decrypted protected-record buffers
group epoch secret and epoch PRK
TreeKEM path/root secrets, node decapsulation keys, and wrap material
backend scratch arenas
```

A failed receive preserves persistent state but still erases every provisional
candidate. A successful receive erases both candidates and replaced old state
after atomic commit.

Panic-unwind builds MUST keep secret values in RAII containers. Abort-on-panic
builds lose destructor guarantees, so process isolation, dump controls, and
restart policy become more important; documentation must state the chosen
panic model.

## 7. Backend scratch

ML-KEM and ML-DSA implementations may create large intermediate buffers. The
backend adapter MUST document:

- exact scratch sizes and allocation locations;
- whether secret-dependent temporaries exist on the stack, heap, SIMD
  registers, or backend-owned memory;
- cleanup guarantees on success and failure;
- constant-time claims and supported platforms; and
- known-answer/self-test behavior.

Reusable scratch arenas are single-operation, non-concurrent, fixed-capacity,
and zeroized before reuse and after the call. They MUST NOT be shared between
identities or sessions without an intervening complete wipe.

## 8. OS hardening

Where available and operationally safe:

- request page locking for long-lived identity and live session state;
- exclude secret mappings from core dumps;
- disable or tightly control process dumps and debugger attachment;
- use encrypted swap and hibernation or disable them for the service;
- avoid secrets in environment variables and command-line arguments;
- isolate cryptographic work in a least-privileged process;
- prevent secrets from entering telemetry, tracing, crash reports, and metrics;
  and
- clear inherited file descriptors and child-process environments.

Failure to lock memory MUST follow explicit deployment policy: either fail
closed for high-assurance mode or continue with a visible local warning.
Silently claiming locked memory is forbidden.

## 9. Persistence and rollback

Persisting ratchet state naively creates nonce/key reuse after rollback. v1
therefore specifies no live-session persistence. A process restart closes all
sessions and requires a new authenticated hybrid handshake.

Identity signing keys may be persisted only through an OS keystore, HSM, or an
encrypted key file whose key derivation, access control, backup, and recovery
policy are separately documented. Group rosters/commit hashes may be
persisted, but group chain keys and TreeKEM private paths are not; restart
requires a fresh authenticated group epoch/tree welcome.

## 10. Shutdown and full wipe

Graceful shutdown:

```text
1. Stop accepting new work.
2. Cancel and join protocol transactions.
3. Close sessions/groups and erase live state.
4. Drain/wipe any scratch cleanup queue.
5. Erase backend arenas and cached one-time keys.
6. Release locked mappings.
7. Exit without serializing live secrets.
```

Forced termination cannot guarantee destructors. Deployment hardening and
short secret lifetimes are the mitigation.

## 11. Verification

Tests MUST cover:

- cleanup after every injected error point;
- transaction drop before and after commit;
- skipped-key eviction/use/close;
- handshake and refresh abort;
- group epoch/mode/tree installation and fork rejection;
- scratch cleanup on backend failure;
- shutdown queue draining; and
- absence of secret traits through compile-fail tests.

Memory inspection tests can show that managed buffers are overwritten, but
MUST NOT be presented as proof that no copies remain elsewhere.
