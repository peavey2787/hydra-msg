# HYDRA-MSG

HYDRA-MSG is a Rust/WASM encrypted messaging SDK for app developers.

It gives apps a simple way to create identities, add contacts, establish sessions, send encrypted messages, receive encrypted messages, attach files/bytes, use small lobbies, and export encrypted backups.

## Navigation

- [How HYDRA messaging works](docs/impl/message-flow/README.md)
- [Spec docs and repo structure](docs/spec/README.md)
- [Crates](crates/README.md)
- [Examples](examples/README.md)
- [Public developer API](docs/spec/public-developer-api.md)
- [Benchmark notes](docs/validation/benchmark-results.md)

## Simple mental model

```text
open encrypted local HYDRA store
  -> create or import your identity
  -> exchange contact cards over any app carrier
  -> establish a session with the contact
  -> send encrypted HYDRA envelopes over any app carrier
```

A normal HYDRA message is key/session based: the receiver needs peer key material and an active session to decrypt. Apps can support anonymous chats by using one-time HYDRA identities and contact cards, but unlinkability across chats requires fresh identities per chat/lobby and no contact-card reuse. Relays only see opaque HYDRA bytes, but they may still see timing, IP, and routing metadata unless the carrier layer hides that too.

Current storage boundary: normal local state is always opened with a state password and sealed into `state-v2.hydra`. Identity password protection and the state password KDF are not memory-hard yet, and contact cards/lobby invites intentionally expose metadata to recipients.

For the detailed flow, see [How HYDRA messaging works](docs/impl/message-flow/README.md).

## Super-simple app shape

Bob's app imports Alice's contact card, starts a session, and sends a message:

```rust
use hydra_msg::{Hydra, HydraMessage, HydraResult};

fn bob_sends_to_alice() -> HydraResult<()> {
    // Open Bob's local HYDRA store for this app/device.
    let mut bob = Hydra::open_default("bob-state-password")?;

    // Create or import Bob's identity, then unlock it for this run.
    let bob_id = bob.generate_id("bob-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    // Alice's contact card arrives through the app carrier:
    // QR, invite link, WebRTC, relay, mailbox, file, or manual copy/paste.
    let alice_card = app_wait_for_alice_contact_card()?;
    let alice = bob.add_contact(alice_card)?;

    // Optional but recommended: compare the safety code with Alice through
    // another channel before showing the contact as verified in the app UI.
    // bob.verify_contact(alice.id(), confirmed_safety_code)?;

    // Create a HYDRA handshake offer and send those opaque bytes to Alice.
    let offer = bob.init_handshake(alice.id())?;
    app_send_to_alice(offer.as_bytes())?;

    // Wait for Alice's opaque handshake answer and finish the session.
    let answer = app_wait_for_alice_answer()?;
    bob.finish_handshake(answer)?;

    // Encrypt a message for Alice. The app carrier only moves the envelope bytes.
    let envelope = bob.send(alice.id(), HydraMessage::text("hello Alice"))?;
    app_send_to_alice(envelope.as_bytes())?;

    Ok(())
}
```

Alice's app shares her contact card, answers Bob's handshake, and receives the message:

```rust
use hydra_msg::{Hydra, HydraResult};

fn alice_receives_from_bob() -> HydraResult<()> {
    // Open Alice's local HYDRA store for this app/device.
    let mut alice = Hydra::open_default("alice-state-password")?;

    // Create or import Alice's identity, then unlock it for this run.
    let alice_id = alice.generate_id("alice-password")?;
    alice.set_active_id(alice_id, "alice-password")?;

    // Share Alice's contact card with Bob through the app carrier.
    let alice_card = alice.create_contact_card()?;
    app_send_to_bob(alice_card)?;

    // Wait for Bob's opaque handshake offer, then create an answer.
    let offer = app_wait_for_bob_offer()?;
    let answer = alice.reply_handshake(offer)?;
    app_send_to_bob(answer.as_bytes())?;

    // Wait for Bob's encrypted HYDRA envelope and decrypt it locally.
    let envelope = app_wait_for_bob_message()?;
    let message = alice.receive(envelope)?;

    println!("Alice received: {}", message.text()?);
    Ok(())
}
```

The `app_*` functions are your app's carrier layer. HYDRA does not care whether those bytes move over WebRTC, files, QR codes, HTTP, a relay, a mailbox, libp2p, or manual copy/paste.

Runnable examples are in [examples](examples/README.md).

## Repository layout

```text
crates/      maintained Rust components
examples/    runnable examples over the public SDK
qa/          local check scripts and validation tooling
docs/        specs, implementation notes, validation notes, future work, and AI working notes
```

For the full folder map, see [Repository structure](docs/spec/README.md).

## Benchmark snapshot

```text
Samsung Galaxy S20 Ultra, browser WASM, 1 KiB payload:
  handshake avg:      10.0 ms
  send+receive avg:    0.0775 ms

ASUS TUF Ryzen 7 A16 laptop, browser WASM, 1 KiB payload:
  handshake avg:       5.7333 ms
  send+receive avg:    0.0521 ms

Desktop PC, browser WASM, 1 KiB payload:
  handshake avg:       4.6633 ms
  send+receive avg:    0.0412 ms

BLU M8L (Original), released August 2020, 1GB RAM, Android 11 Go edition,
browser WASM, 1 KiB payload:
  handshake avg:     162.5 ms
  send+receive avg:    1.27 ms
```

See [Benchmark notes](docs/validation/benchmark-results.md) for the full table.
