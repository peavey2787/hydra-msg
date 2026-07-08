use hydra_app_core::{AppGroup, AppIdentity};
use hydra_group::GroupRole;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = AppIdentity::generate()?;
    let bob = AppIdentity::generate()?;

    let mut alice_group = AppGroup::create_lite(&alice, GroupRole::Member)?;
    let welcome = alice_group.add_lite_member(&alice, bob.public_identity(), GroupRole::Member)?;
    let mut bob_group = AppGroup::install_lite_welcome(&bob, welcome)?;

    let outbound = alice_group.send_signed(&alice, b"hello group")?;
    let received = bob_group.receive_signed(outbound.as_envelope())?;
    println!(
        "group message: {}",
        String::from_utf8_lossy(received.content())
    );
    Ok(())
}
