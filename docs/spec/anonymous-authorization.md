# Anonymous authorization

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

This note defines the current anonymous-but-authorized boundary for the app-facing facade.

## Goal

Anonymous authorization means a user can prove that an action is allowed without using the normal contact identity as the authorization handle. It is separate from message encryption, contact cards, lobby membership, and carrier anonymity.

Current flows that need this boundary include:

```text
private lobby join permission
invite-only mailbox posting
paid or quota-limited relay access
rate-limited app actions
event or campaign access without a reusable account id
```

## Current implementation choice

The current facade implements a bounded bearer-token stopgap:

```text
issuer creates one random token for one scope/action/expiry
holder presents that token later
verifier validates an HMAC tag with its local issuer secret
verifier records a nullifier after acceptance
reusing the same token is rejected as replay/double-spend
```

This gives one-time authorization without revealing a HYDRA contact id, identity id, lobby member id, or session id. Repeated token issuance for the same scope/action produces different token bytes and different nullifiers.

This does not provide blind issuance. An issuer that observes both issuance and redemption can still correlate through app metadata, transport metadata, timing, or its own issuance records. Apps needing stronger anonymous authorization should use blind credentials, zero-knowledge membership proofs, or a mixnet/proxy/carrier design around HYDRA.

## Current public API

```rust
use hydra_msg::{HydraAnonymousAuthPolicy, HydraResult};

fn issue_and_accept(mut gate: hydra_msg::Hydra) -> HydraResult<()> {
    let policy = HydraAnonymousAuthPolicy::new("private-lobby", "join")
        .with_expiry(1_900_000_000);

    let token = gate.issue_anonymous_auth_token(policy)?;
    let grant = gate.accept_anonymous_auth_token(
        token,
        "private-lobby",
        "join",
        1_800_000_000,
    )?;

    println!("accepted nullifier: {}", grant.nullifier().hex());
    Ok(())
}
```

## Replay, double-spend, revocation, and expiry

The verifier stores spent nullifiers in encrypted local state. A token can be accepted once by a verifier using the same anonymous authorization issuer secret. A second acceptance of the same token fails.

Revocation marks the token nullifier as spent before normal acceptance:

```text
revoke_anonymous_auth_token(token, expected_scope, expected_action)
```

Expiry is checked by the app-supplied Unix timestamp at acceptance. HYDRA does not provide trusted time; the app/verifier must supply a policy-appropriate time source.

## Privacy boundaries

The token format exposes:

```text
scope
action
expiry
random nonce
verification tag
```

It does not expose:

```text
contact id
identity id
lobby member id
session id
message id
```

For unlinkability across chats or lobbies, apps must use fresh scopes and fresh tokens. Reusing a token, scope, mailbox id, invite, relay account, or network endpoint can still link activity outside HYDRA encryption.

## Future stronger layer

A stronger anonymous-but-authorized layer should replace or wrap bearer tokens with one of these designs:

```text
blind credentials for unlinkable issuance and redemption
zero-knowledge membership proofs for private eligibility
nullifier-based proofs for one-time use without identity reveal
rate-limit credentials with expiry and revocation accumulators
```

That layer must remain separate from the normal message encryption path and contact identity model.
