#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

use hydra_app_core::{HydraApp, RememberMePolicy};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = env::temp_dir().join("hydra-gui-identity-contacts-example");
    let _ = fs::remove_dir_all(&data_dir);
    let mut app = HydraApp::open(&data_dir, "state-password")?;
    let id = app.generate_identity("Primary", "identity-password")?;
    app.set_remember_me(id, RememberMePolicy::Session)?;
    let card = app.create_labeled_contact_card("Reference app user")?;
    println!("identity={}", id.hex());
    println!("contact_card={}", String::from_utf8_lossy(&card));
    drop(app);
    fs::remove_dir_all(data_dir)?;
    Ok(())
}
