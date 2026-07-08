# HYDRA-MSG normative state machines

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

This document is the consolidated transition authority. A transition not
listed here is invalid. Every receive transition is provisional until all
cryptographic, canonical, policy, replay, and padding checks succeed.

## 1. Common transaction rule

```text
snapshot immutable parent state
derive into zeroizing provisional state
authenticate and validate complete object
perform replay/fork/conflict checks
atomically install candidate state
erase replaced and provisional secrets
deliver at most once
```

Any failure before installation preserves the parent state and produces no
application delivery.

## 2. Handshake

| Role/state | Input/action | Preconditions | Next state |
|---|---|---|---|
| initiator `New` | create INIT | fresh entropy, expected peer/trust policy configured | `InitSent` |
| responder `New` | receive INIT | exact Standard envelope, trust and signature valid | `InitVerified` |
| responder `InitVerified` | create RESP | fresh entropy, KEM/DH valid | `RespSent` |
| initiator `InitSent` | receive RESP | transcript, trust, signature, KEM/DH, confirmation valid | `RespVerified` |
| initiator `RespVerified` | create FINISH | candidate state complete | `Established` after immutable FINISH emission |
| responder `RespSent` | receive FINISH | finish AEAD and transcript/session match | `Established` |
| any provisional state | definitive failure/timeout | none | `Closed` |

Exact retransmission preserves state. A different record for the same
handshake instance is rejected.

## 3. Ordered and out-of-order receive

| Condition | Provisional work | Commit |
|---|---|---|
| `n == next_index` | derive one candidate | install chain `n+1`, replay bit |
| `next_index < n <= next_index + bound` | derive bounded candidates | install chain `n+1`, retain missing one-use keys |
| older `n` with skipped key | try that key | erase key and set replay bit on full success |
| replayed/too old/excessive gap | none or bounded lookup | none |
| any authentication/inner failure | erase candidates | none |

An ambiguous send consumes its reserved index. Only identical ciphertext may
be retransmitted.

The replay window has `MAX_SKIP + 1 = 257` positions: the current highest
authenticated index plus its 256 predecessors. Therefore gaps 255 and 256 are
admissible, while gap 257 is rejected without changing state.

## 4. Refresh

```text
Idle -> InitPending -> Quiesced -> RespPending -> FinishPending -> Installed
```

REFRESH_INIT and REFRESH_RESP are ordinary parent-chain records and consume
their message indices. The exact `old_*_send_index` in a refresh core is the
next send index after that core's immutable envelope; the receive index is the
next expected parent index observed when constructing the core.

After emitting REFRESH_INIT, the initiator sends no more parent-session
application records. After accepting REFRESH_INIT, the responder does the
same. Each may continue authenticating already emitted parent records while
the refresh runs, but only the required refresh control record may be newly
sent. REFRESH_RESP fixes the responder cutover positions. Receipt of a refresh
control record advances/skips its parent receive chain under the ordinary
bounded rules.

The initiator installs after constructing immutable REFRESH_FINISH; the
responder installs only after authenticating it. Installation erases all
parent chains, skipped keys, and undelivered parent records, including missing
records below a cutover position. No parent record is delivered afterward.

The lexicographically lower concurrent `refresh_id` wins. Losing candidates
are erased before responding. A valid local/remote CLOSE aborts refresh and
close takes precedence. Other aborts erase candidate refresh state and lift
the application-send pause only if the unchanged parent state remains usable.

## 5. Close

| State | Event | Result |
|---|---|---|
| `Established` | emit authenticated CLOSE | `Closing`; no new sends |
| `Established`/`Closing` | receive valid CLOSE | erase session, `Closed` |
| `Closing` | identical CLOSE retry | remain `Closing` |
| any | transport loss/timeout | local close; no delivery claim |

## 6. Group commit and fork

| Group state | Event | Result |
|---|---|---|
| `Active` | valid sole child of parent | atomically install epoch/state, remain `Active` |
| `Active` | incomplete authenticated fragments | remain `Active`; buffer bounded candidate, continue parent delivery |
| `AwaitingTransition` | joining device receives incomplete welcome/snapshot | buffer bounded candidate; no group delivery |
| `AwaitingTransition` | complete valid welcome/snapshot | install candidate, `Active` |
| `AwaitingTransition` | invalid/expired object | erase candidate, remain without group state |
| `Active` | second distinct valid child of same parent | `Forked` |
| `Forked` | application-authorized resolution | fresh successor state or `Closed` |

Arrival order never resolves a fork. Parent application delivery stops while
`Forked`. Incomplete candidate fragments never mutate or suspend the active
parent state; resource limits and expiration apply to their separate buffer.

## 7. Mode transition

`MODE_CHANGE` verifies completely under the parent governance and mode. It
then validates the candidate roster/roles/policy, constructs a fresh
membership mechanism for the new mode, resets every sender chain/replay window
to zero, installs atomically, and erases the complete parent mechanism.
Partial cross-mode state is never usable.

## 8. Identity rotation

```text
Stable -> RotationCandidate -> SessionsClosing -> Reauthenticated
```

Both old/new signatures, monotonic rotation index, trust policy, and affected
group commits must validate before accepting the candidate. Acceptance closes
old sessions. No session key, chain, or TreeKEM private key crosses to the new
identity.

## 9. Device revocation

```text
Trusted -> RevocationCandidate -> Revoked
```

On a valid monotonic policy-authorized record, new handshakes from the device
are rejected immediately, its sessions close, and each affected group enters
a fresh removal epoch. Revocation is not rolled back by stale state and does
not retract delivered plaintext.

## 10. Crash behavior

No live state is recoverable from ordinary persistence. A crash discards
provisional and live session/group traffic secrets. Restart establishes new
sessions and obtains fresh group welcomes as specified by
`persistence-and-rollback.md`.
