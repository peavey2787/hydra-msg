#![allow(dead_code)]

// Each fuzz target is compiled as a separate binary and intentionally uses only a subset
// of these shared helpers. Suppress per-binary dead-code noise without hiding warnings
// in the target implementations themselves.
use hydra_msg::{ContactId, Hydra};
use std::path::PathBuf;

pub fn bounded(data: &[u8], max: usize) -> Vec<u8> {
    data[..data.len().min(max)].to_vec()
}

pub fn temp_case_dir(prefix: &str, data: &[u8]) -> PathBuf {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in data.iter().take(512) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    std::env::temp_dir().join(format!(
        "hydra-coverage-fuzz-{prefix}-{}-{hash:016x}",
        std::process::id()
    ))
}

pub fn fresh(path: PathBuf) -> Option<Hydra> {
    let _ = std::fs::remove_dir_all(&path);
    Hydra::open(path, "state-pw").ok()
}

pub fn paired(prefix: &str, data: &[u8]) -> Option<(Hydra, Hydra, ContactId, ContactId)> {
    let base = temp_case_dir(prefix, data);
    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    let mut alice = fresh(alice_dir)?;
    let mut bob = fresh(bob_dir)?;
    let alice_id = alice.generate_id("pw").ok()?;
    let bob_id = bob.generate_id("pw").ok()?;
    alice.set_active_id(alice_id, "pw").ok()?;
    bob.set_active_id(bob_id, "pw").ok()?;
    let alice_contact = bob.add_contact(alice.create_contact_card().ok()?).ok()?;
    let bob_contact = alice.add_contact(bob.create_contact_card().ok()?).ok()?;
    let offer = alice.init_handshake(bob_contact.id()).ok()?;
    let answer = bob.reply_handshake(offer).ok()?;
    alice.finish_handshake(answer).ok()?;
    Some((alice, bob, alice_contact.id(), bob_contact.id()))
}
