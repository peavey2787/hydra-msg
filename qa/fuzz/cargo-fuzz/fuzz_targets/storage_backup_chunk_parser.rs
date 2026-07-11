#![no_main]

mod common;

use hydra_msg::Hydra;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("storage-backup", data);
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::create_dir_all(&base);
    let _ = std::fs::write(base.join("state.hydra"), data);
    let _ = Hydra::open(&base, "state-pw");

    if let Some(mut hydra) = common::fresh(base.join("backup")) {
        let _ = hydra.verify_backup(data, "backup-pw");
        let _ = hydra.import_backup(data, "backup-pw");
        if let Ok(valid) = hydra.export_backup("backup-pw") {
            let mut mutated = valid;
            if let Some(first) = mutated.first_mut() {
                *first ^= data.first().copied().unwrap_or(0xa5);
            }
            if !data.is_empty() {
                mutated.extend_from_slice(&data[..data.len().min(32)]);
            }
            let _ = hydra.verify_backup(&mutated, "backup-pw");
            let _ = hydra.import_backup(&mutated, "backup-pw");
        }
    }
    let _ = std::fs::remove_dir_all(&base);
});
