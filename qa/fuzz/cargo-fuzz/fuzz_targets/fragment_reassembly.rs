#![no_main]

mod common;

use hydra_msg::HydraMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((mut alice, mut bob, _alice_contact, bob_contact)) = common::paired("fragment", data) else {
        return;
    };
    let _ = alice.set_packet_size(1024);
    let _ = bob.set_packet_size(1024);
    let mut payload = vec![0x42; 4096];
    payload.extend_from_slice(&common::bounded(data, 4096));
    if let Ok(mut packets) = alice.send(bob_contact, HydraMessage::bytes(payload)) {
        packets.reverse();
        for packet in packets {
            let _ = bob.receive(packet.clone());
            let mut mutated = packet.into_bytes();
            if !mutated.is_empty() && !data.is_empty() {
                let index = data.len() % mutated.len();
                mutated[index] ^= data[0];
            }
            let _ = bob.receive(mutated);
        }
    }
    let _ = bob.receive(data);
    let _ = std::fs::remove_dir_all(common::temp_case_dir("fragment", data));
});
