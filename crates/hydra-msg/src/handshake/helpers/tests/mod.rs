use super::*;
use crate::{ContactId, Hydra, HydraMsgError, IdentityId};
use std::cmp::Ordering;

fn fresh(path: &str) -> Hydra {
    let _ = std::fs::remove_dir_all(path);
    let mut hydra = Hydra::open(path, "state-pw").unwrap();
    let id = hydra.generate_id("pw").unwrap();
    hydra.set_active_id(id, "pw").unwrap();
    hydra
}

fn contacts(alice: &mut Hydra, bob: &mut Hydra) -> (ContactId, ContactId) {
    let alice_contact = bob
        .add_contact(alice.create_contact_card().unwrap())
        .unwrap();
    let bob_contact = alice
        .add_contact(bob.create_contact_card().unwrap())
        .unwrap();
    (alice_contact.id(), bob_contact.id())
}

fn predecessor(value: [u8; 32]) -> [u8; 32] {
    let mut out = value;
    for index in (0..out.len()).rev() {
        if out[index] != 0 {
            out[index] -= 1;
            out[index + 1..].fill(u8::MAX);
            return out;
        }
    }
    panic!("fingerprint unexpectedly has no predecessor")
}

fn successor(value: [u8; 32]) -> [u8; 32] {
    let mut out = value;
    for index in (0..out.len()).rev() {
        if out[index] != u8::MAX {
            out[index] += 1;
            out[index + 1..].fill(0);
            return out;
        }
    }
    panic!("fingerprint unexpectedly has no successor")
}

mod matrix;
