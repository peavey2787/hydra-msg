#![no_main]

mod common;

use hydra_msg::HydraMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("message-codec", data);
    let Some(mut hydra) = common::fresh(base.join("parser")) else {
        return;
    };
    let _ = hydra.import_messages(data);

    if let Some((mut alice, mut bob, _alice_contact, bob_contact)) = common::paired("message-flow", data) {
        let bounded = common::bounded(data, 8192);
        let mut message = HydraMessage::bytes(bounded.clone());
        if !bounded.is_empty() {
            if let Ok(attached) = message.clone().attach_bytes("fuzz.bin", bounded.clone()) {
                message = attached;
            }
        }
        if let Ok(packets) = alice.send(bob_contact, message) {
            for packet in packets {
                let _ = bob.receive(packet.clone());
                let mut tampered = packet.into_bytes();
                let index = data.len() % tampered.len().max(1);
                if let Some(byte) = tampered.get_mut(index) {
                    *byte ^= 0x5a;
                }
                let _ = bob.receive(tampered);
            }
        }
    }
    let _ = std::fs::remove_dir_all(common::temp_case_dir("message-codec", data));
    let _ = std::fs::remove_dir_all(common::temp_case_dir("message-flow", data));
});
