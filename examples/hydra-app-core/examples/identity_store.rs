use std::path::PathBuf;

use hydra_app_core::IdentityStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from("hydra-identity-store.example.hydraid");
    let password = b"replace with a user supplied high-entropy password";

    let store = IdentityStore::create(&path, password)?;
    let loaded = IdentityStore::load_for_device(&path, password, store.device_id())?;
    println!(
        "loaded identity generation {} for device {:02x?}",
        loaded.generation(),
        loaded.device_fingerprint().0
    );
    std::fs::remove_file(path).ok();
    Ok(())
}
