use hydra_msg::{Hydra, HydraResult};

fn main() -> HydraResult<()> {
    let _ = std::fs::remove_dir_all("target/examples/contact_card/alice");
    let _ = std::fs::remove_dir_all("target/examples/contact_card/bob");
    let _ = std::fs::remove_dir_all("target/examples/contact_card/restored");

    let mut alice = Hydra::open("target/examples/contact_card/alice")?;
    let mut bob = Hydra::open("target/examples/contact_card/bob")?;

    let alice_id = alice.generate_id("alice-password")?;
    let bob_id = bob.generate_id("bob-password")?;
    alice.set_active_id(alice_id, "alice-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    let alice_card = alice.create_contact_card()?;
    println!(
        "Alice contact card:\n{}",
        String::from_utf8_lossy(&alice_card)
    );

    let alice_contact = bob.add_contact(alice_card)?;
    let safety_code = alice_contact.safety_code();
    bob.verify_contact(alice_contact.id(), safety_code.clone())?;

    println!("Bob added Alice as contact {}", alice_contact.id().hex());
    println!("Safety code: {safety_code}");
    println!(
        "Verified: {}",
        bob.get_contact(alice_contact.id())?.verified()
    );

    let exported = bob.export_contacts()?;
    let mut restored = Hydra::open("target/examples/contact_card/restored")?;
    restored.import_contacts(exported)?;
    println!("Restored contact count: {}", restored.list_contacts().len());

    Ok(())
}
