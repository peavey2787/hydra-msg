#![no_main]

use hydra_envelope::decode_outer_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_outer_header(data);
});
