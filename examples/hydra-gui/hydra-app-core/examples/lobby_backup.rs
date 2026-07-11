#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

use hydra_app_core::{HydraApp, HydraLobbyPolicy};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = env::temp_dir().join("hydra-gui-lobby-backup-example");
    let _ = fs::remove_dir_all(&base);
    let mut app = HydraApp::open(&base, "state-password")?;
    app.generate_identity("Primary", "identity-password")?;
    let lobby = app.create_lobby(HydraLobbyPolicy::new("Reference lobby", 16))?;
    let invite = app.create_lobby_invite(lobby.id())?;
    let backup = app.export_backup("backup-password")?;
    app.verify_backup(&backup, "backup-password")?;
    println!("lobby={}", lobby.id().hex());
    println!("invite_bytes={}", invite.len());
    println!("backup_bytes={}", backup.len());
    drop(app);
    fs::remove_dir_all(base)?;
    Ok(())
}
