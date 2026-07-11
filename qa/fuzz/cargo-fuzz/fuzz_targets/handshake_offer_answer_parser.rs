#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("handshake-parser", data);
    let Some(mut hydra) = common::fresh(base.join("peer")) else {
        return;
    };
    if let Ok(id) = hydra.generate_id("pw") {
        let _ = hydra.set_active_id(id, "pw");
    }
    let _ = hydra.reply_handshake(data);
    let _ = hydra.finish_handshake(data);

    if let Some((mut alice, mut bob, _alice_contact, bob_contact)) = common::paired("handshake-valid", data) {
        if let Ok(offer) = alice.init_handshake(bob_contact) {
            let mut mutated = offer.into_bytes();
            let index = data.len() % mutated.len().max(1);
            if let Some(byte) = mutated.get_mut(index) {
                *byte ^= 0x80;
            }
            let _ = bob.reply_handshake(mutated);
        }
    }
    let _ = std::fs::remove_dir_all(common::temp_case_dir("handshake-valid", data));
});
