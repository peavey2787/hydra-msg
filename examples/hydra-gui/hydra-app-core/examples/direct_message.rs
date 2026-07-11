#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

use hydra_app_core::{HydraApp, HydraMessage};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = env::temp_dir().join("hydra-gui-direct-message-example");
    let _ = fs::remove_dir_all(&base);
    let mut alice = HydraApp::open(base.join("alice"), "alice-state")?;
    let mut bob = HydraApp::open(base.join("bob"), "bob-state")?;
    alice.generate_identity("Alice", "alice-id")?;
    bob.generate_identity("Bob", "bob-id")?;

    let alice_contact = bob.add_contact(alice.create_labeled_contact_card("Alice")?)?;
    let bob_contact = alice.add_contact(bob.create_labeled_contact_card("Bob")?)?;
    let offer = alice.handshake_offer(bob_contact.id())?;
    let answer = bob.handshake_answer(offer)?;
    alice.finish_handshake(answer)?;

    for packet in alice.send_message(bob_contact.id(), HydraMessage::text("hello"))? {
        if let Some(message) = bob.receive_message(packet)? {
            println!("{}: {}", alice_contact.label(), message.text()?);
        }
    }
    drop(alice);
    drop(bob);
    fs::remove_dir_all(base)?;
    Ok(())
}
