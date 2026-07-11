#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("contact-card", data);
    let Some(mut hydra) = common::fresh(base) else {
        return;
    };
    let _ = hydra.preview_contact_card(data);
    let _ = hydra.add_contact(data);
    let _ = hydra.import_contacts(data);
});
