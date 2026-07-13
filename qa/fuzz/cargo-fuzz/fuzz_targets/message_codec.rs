#![no_main]

use hydra_msg::{fuzzing, HydraMessage};
use libfuzzer_sys::fuzz_target;

const MAX_FAST_MESSAGE_BYTES: usize = 8192;

fuzz_target!(|data: &[u8]| {
    let _ = fuzzing::decode_message_payload(data);
    let _ = fuzzing::decode_message_state_line(data);

    let bounded = &data[..data.len().min(MAX_FAST_MESSAGE_BYTES)];
    let split = bounded.len() / 2;
    let mut message = HydraMessage::bytes(bounded[..split].to_vec());
    if bounded.first().is_some_and(|byte| *byte & 1 == 1) {
        message = message
            .attach_bytes("fuzz.bin", bounded[split..].to_vec())
            .expect("bounded in-memory attachment must be accepted");
    }

    let packed = fuzzing::encode_message_payload(&message)
        .expect("bounded in-memory message must encode");
    let decoded = fuzzing::decode_message_payload(&packed)
        .expect("production codec must decode its own output");
    assert_eq!(decoded.plaintext(), message.plaintext());
    assert_eq!(decoded.attachments(), message.attachments());
});
