#![no_main]

mod common;

use hydra_msg::HydraMessage;
use libfuzzer_sys::fuzz_target;

const MAX_STATEFUL_MESSAGE_BYTES: usize = 2048;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("message-stateful-flow", data);
    let Some((mut alice, mut bob, _alice_contact, bob_contact)) =
        common::paired("message-stateful-flow", data)
    else {
        let _ = std::fs::remove_dir_all(base);
        return;
    };

    let bounded = common::bounded(data, MAX_STATEFUL_MESSAGE_BYTES);
    let mut message = HydraMessage::bytes(bounded.clone());
    if !bounded.is_empty() {
        message = message
            .attach_bytes("fuzz.bin", bounded)
            .expect("bounded in-memory attachment must be accepted");
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

    let _ = std::fs::remove_dir_all(base);
});
