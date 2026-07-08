use hydra_app_core::AppIdentity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = AppIdentity::generate()?;
    println!(
        "created identity fingerprint: {:02x?}",
        identity.fingerprint().0
    );
    Ok(())
}
