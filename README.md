# HYDRA-MSG

HYDRA-MSG is a Rust/WASM encrypted messaging SDK for app developers.

It gives apps a simple way to create identities, add contacts, establish sessions, send encrypted messages, receive encrypted messages, attach files/bytes, use small lobbies, and export encrypted backups.

## Navigation

- [How HYDRA messaging works](docs/project/message-flow/README.md)
- [Crates](crates/README.md)
- [Examples](examples/README.md)
- [Public developer API](docs/project/public-developer-api.md)
- [Benchmark notes](docs/project/benchmark-results.md)
- [Roadmap](docs/roadmap.md)

## Simple mental model

```text
open local HYDRA store
  -> create or import your identity
  -> exchange contact cards over any app carrier
  -> establish a session with the contact
  -> send encrypted HYDRA envelopes over any app carrier
```

A normal HYDRA message is contact/session based. Apps can still create anonymous-feeling flows by using one-time identities, temporary contact cards, invite links, QR codes, or relay/mailbox pickup, but HYDRA still needs peer key material and a session internally so the receiver can decrypt.

For the detailed flow, see [How HYDRA messaging works](docs/project/message-flow/README.md).

## Super-simple app shape

Bob's app starts a session with Alice and sends a message:

```rust
use hydra_msg::{Hydra, HydraMessage, HydraResult};

fn bob_sends_to_alice() -> HydraResult<()> {
    // Open Bob's local HYDRA store.
    let mut bob = Hydra::open_default()?;

    // Create Bob's local identity and unlock it for this run.
    let bob_id = bob.generate_id("bob-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    // Alice's contact card arrives through your app: QR, invite link,
    // file, WebRTC, relay, mailbox, or any other carrier.
    let alice = bob.add_contact(app_wait_for_alice_contact_card()?)?;

    // Optional but recommended: show this code to the user and let them
    // confirm it with Alice before marking the contact as verified.
    // bob.verify_contact(alice.id(), confirmed_safety_code)?;

    // Create a HYDRA handshake offer and send those opaque bytes to Alice.
    let offer = bob.init_handshake(alice.id())?;
    app_send_to_alice(offer.as_bytes())?;

    // Wait for Alice's opaque handshake answer and finish the session.
    let answer = app_wait_for_alice_answer()?;
    bob.finish_handshake(answer)?;

    // Send an encrypted HYDRA envelope through your app carrier.
    let envelope = bob.send(alice.id(), HydraMessage::text("hello Alice"))?;
    app_send_to_alice(envelope.as_bytes())?;

    Ok(())
}
```

Alice's app shares her contact card, answers Bob, and receives the message:

```rust
use hydra_msg::{Hydra, HydraResult};

fn alice_receives_from_bob() -> HydraResult<()> {
    // Open Alice's local HYDRA store.
    let mut alice = Hydra::open_default()?;

    // Create Alice's local identity and unlock it for this run.
    let alice_id = alice.generate_id("alice-password")?;
    alice.set_active_id(alice_id, "alice-password")?;

    // Share Alice's contact card with Bob through your app carrier.
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
docs/        project docs grouped by purpose
```

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

See [Benchmark notes](docs/project/benchmark-results.md) for the full table.
