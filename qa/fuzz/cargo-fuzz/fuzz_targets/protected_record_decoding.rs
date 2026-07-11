#![no_main]

use hydra_core::types::EnvelopeClass;
use hydra_envelope::decode_protected_record;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for class in [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ] {
        let _ = decode_protected_record(class, data);
    }
});
