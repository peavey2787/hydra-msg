# QSSM Authorization and Privacy Layer for HYDRA-MSG

Status: future extension concept.

This document explains how `qssm-rs` (https://github.com/peavey2787/qssm-rs) could later be used with HYDRA-MSG as an optional zero-knowledge authorization and privacy layer.

This is not part of the HYDRA-MSG v1 core implementation roadmap. HYDRA-MSG must first implement and validate the base post-quantum messaging protocol.

## 1. Core distinction

HYDRA-MSG and QSSM solve different problems.

```text
HYDRA-MSG = encrypted post-quantum messaging
QSSM      = zero-knowledge policy / authorization proofs
```

QSSM should not replace HYDRA-MSG handshake, encryption, ratchets, signatures, replay protection, refresh, or group key management.

Instead, QSSM can later be layered around HYDRA-MSG to prove that a user is allowed to perform an action without revealing the private credential, identity, or membership witness behind that authorization.

In short:

```text
QSSM proves permission.
HYDRA-MSG protects communication.
```

## 2. Possible use cases

A future QSSM layer could support:

* private group admission;
* anonymous or pseudonymous group membership;
* proof-gated invites;
* proof-of-role without revealing identity;
* proof-of-payment or proof-of-access;
* rate-limited anonymous sending;
* one-vote-per-member proposals;
* anonymous-but-authorized admin actions;
* private credential checks;
* anti-spam checks without account disclosure.

Example claim:

```text
I am allowed to join this group,
but I do not reveal which authorized member or credential I am using.
```

## 3. Example architecture

A HYDRA group may publish a public authorization root or policy commitment:

```text
group_policy_id
group_members_root
group_epoch
allowed_actions
```

A user privately holds:

```text
member_secret
credential
membership witness
role witness
policy witness
```

The user generates a QSSM proof showing that the private witness satisfies the public policy.

A HYDRA join or send request could include:

```text
HYDRA action message
QSSM policy id
QSSM proof
public nullifier
public proof outputs
```

The receiver verifies the QSSM proof before accepting the HYDRA action.

## 4. Required transcript binding

Every QSSM proof used with HYDRA-MSG must be bound to the HYDRA context.

At minimum, the proof statement should bind to:

```text
HYDRA-MSG/v1/qssm-auth
group_id
session_id or transcript_hash
epoch
action label
policy id
optional sender/device commitment
```

This prevents replaying a valid proof from one group, epoch, session, or action into another.

Example action labels:

```text
join
send
invite
admin
vote
refresh
role-change
```

A proof valid for `join` must not be reusable as a proof for `send`, `admin`, or `vote`.

## 5. Nullifiers

QSSM proofs may expose a public nullifier to prevent double-use without revealing identity.

Example nullifiers:

```text
join_nullifier = H(member_secret, group_id, epoch, "join")
send_nullifier = H(member_secret, group_id, epoch, send_window, "send")
vote_nullifier = H(member_secret, group_id, proposal_id, "vote")
```

Nullifiers allow the protocol to enforce rules like:

* one join per epoch;
* one vote per proposal;
* N sends per time window;
* no duplicate use of the same private credential.

The nullifier must be action-specific and context-bound.

## 6. Anonymous authorized group mode

A future HYDRA group mode could support anonymous authorized actions.

Instead of proving:

```text
Alice sent this message.
```

the sender proves:

```text
Some valid group member sent this message.
```

This enables stronger sender privacy but changes the accountability model.

The group can verify authorization without learning the sender’s real identity.

## 7. Pseudonymous roster mode

A simpler design is to keep a normal HYDRA group roster, but use pseudonymous leaf keys.

Example:

```text
leaf_42 = pseudonymous HYDRA device key
```

QSSM proves that `leaf_42` is backed by a valid credential or membership witness.

This gives:

```text
authorized pseudonymous membership
```

rather than full anonymity.

## 8. Security boundaries

QSSM can help hide authorization details.

QSSM does not automatically hide:

* IP address;
* timing metadata;
* relay path;
* message size;
* online presence;
* social graph metadata;
* compromised endpoint contents.

Network anonymity requires a separate transport design such as Tor, I2P, mixnets, relays, or other metadata-hiding systems.

## 9. Non-goals

The QSSM layer must not replace:

* HYDRA-MSG key exchange;
* ML-KEM/X25519 hybrid agreement;
* ML-DSA identity signatures;
* AEAD encryption;
* chain ratchets;
* replay protection;
* TreeKEM or group key management;
* transcript authentication;
* state-machine validation.

The QSSM layer is optional authorization/privacy infrastructure, not the base secure messaging protocol.

## 10. Example predicates

A minimal future QSSM integration may start with four predicate families:

### 10.1 Membership predicate

Proves that the user belongs to an authorized set without revealing which member they are.

### 10.2 Credential predicate

Proves possession of a valid credential, invite, access token, payment proof, or capability.

### 10.3 Rate-limit predicate

Proves that the user has not exceeded an allowed action count for a group, epoch, window, or proposal.

### 10.4 Continuity / anchor predicate

Proves continuity with a prior commitment, anchor, heartbeat, or registration without revealing unnecessary private data.

## 11. Suggested future crate

If this feature is added later, it should live outside the HYDRA-MSG core crates.

Possible crate name:

```text
hydra-qssm-auth
```

or:

```text
hydra-zk-auth
```

Responsibilities:

* define QSSM policy bindings;
* verify QSSM proofs;
* bind proofs to HYDRA transcripts;
* manage nullifier validation;
* expose authorization decisions to HYDRA group/session logic.

It should not own HYDRA encryption, ratchets, wire formats, or group key management.

## 12. Roadmap placement

This extension should not block HYDRA-MSG v1.

Recommended placement:

```text
After M6 if used for 1:1 or protected-message authorization.
After M8 if used for group or TreeKEM authorization.
```

The base protocol should remain usable without QSSM.

## 13. Summary

QSSM can become a powerful optional layer for HYDRA-MSG.

It enables:

```text
private authorization
anonymous or pseudonymous group admission
proof-gated actions
rate-limited anonymous participation
credential-based privacy
```

But the core rule remains:

```text
HYDRA-MSG secures the chat.
QSSM proves private authorization.
```