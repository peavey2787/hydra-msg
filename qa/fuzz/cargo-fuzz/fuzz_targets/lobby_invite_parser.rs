#![no_main]

mod common;

use hydra_msg::HydraLobbyPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("lobby-invite", data);
    let Some(mut hydra) = common::fresh(base) else {
        return;
    };
    let _ = hydra.preview_lobby_invite(data);
    let _ = hydra.join_lobby(data);

    if let Ok(lobby) = hydra.create_lobby(HydraLobbyPolicy::new("fuzz", 8)) {
        if let Ok(invite) = hydra.create_lobby_invite(lobby.id()) {
            let mut mutated = invite.into_bytes();
            if !data.is_empty() {
                mutated.extend_from_slice(&data[..data.len().min(16)]);
            }
            let _ = hydra.preview_lobby_invite(&mutated);
            let _ = hydra.join_lobby(&mutated);
        }
    }
});
