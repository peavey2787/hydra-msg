use super::*;
use std::{fs, path::Path};

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

fn small_backup(path: &str) -> Vec<u8> {
    let mut hydra = fresh(path);
    hydra.generate_id("id-pw").unwrap();
    hydra.export_backup("backup-pw").unwrap()
}

fn large_backup(path: &str) -> Vec<u8> {
    let mut hydra = fresh(path);
    let id = hydra.generate_id("id-pw").unwrap();
    hydra.set_active_id(id, "id-pw").unwrap();
    let contact = hydra
        .add_contact(hydra.create_contact_card().unwrap())
        .unwrap();
    hydra
        .store_message(contact.id(), true, vec![b'x'; 96 * 1024], Vec::new())
        .unwrap();
    hydra.export_backup("backup-pw").unwrap()
}

fn state_bytes(path: &str) -> Vec<u8> {
    fs::read(Path::new(path).join(STATE_FILE_NAME)).unwrap()
}

fn lines(bytes: &[u8]) -> Vec<String> {
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(ToOwned::to_owned)
        .collect()
}

fn bytes_from_lines(lines: &[String]) -> Vec<u8> {
    let mut out = lines.join("\n").into_bytes();
    out.push(b'\n');
    out
}

fn chunk_indices(lines: &[String]) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| line.starts_with("chunk\t").then_some(index))
        .collect()
}

fn set_field(lines: &mut [String], field: &str, value: &str) {
    let prefix = format!("{field}\t");
    let line = lines
        .iter_mut()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("missing field {field}"));
    *line = format!("{field}\t{value}");
}

fn rewrite_chunk_index(line: &str, index: usize) -> String {
    let mut parts = line.split('\t');
    assert_eq!(parts.next(), Some("chunk"));
    let _old_index = parts.next().unwrap();
    let ciphertext = parts.next().unwrap();
    assert!(parts.next().is_none());
    format!("chunk\t{index}\t{ciphertext}")
}

fn verify_backup_rejects(bytes: Vec<u8>, label: &str) {
    let verifier = fresh(&format!(
        "target/hydra-msg-test-storage-chunk-reject-{label}"
    ));
    assert!(verifier.verify_backup(bytes, "backup-pw").is_err());
}

#[test]
fn chunked_backup_rejects_missing_duplicate_extra_wrong_count_size_and_index() {
    let backup = small_backup("target/hydra-msg-test-storage-chunk-small-source");
    let original = lines(&backup);
    let chunks = chunk_indices(&original);
    assert_eq!(chunks.len(), 1);

    let mut missing = original.clone();
    missing.remove(chunks[0]);
    verify_backup_rejects(bytes_from_lines(&missing), "missing");

    let mut duplicate = original.clone();
    duplicate.insert(chunks[0] + 1, original[chunks[0]].clone());
    verify_backup_rejects(bytes_from_lines(&duplicate), "duplicate");

    let mut wrong_count = original.clone();
    set_field(&mut wrong_count, "chunk_count", "2");
    verify_backup_rejects(bytes_from_lines(&wrong_count), "wrong-count");

    let mut wrong_index = original.clone();
    wrong_index[chunks[0]] = rewrite_chunk_index(&wrong_index[chunks[0]], 7);
    verify_backup_rejects(bytes_from_lines(&wrong_index), "wrong-index");

    let mut wrong_size = original.clone();
    wrong_size[chunks[0]].push_str("00");
    verify_backup_rejects(bytes_from_lines(&wrong_size), "wrong-size");

    let mut extra = original.clone();
    set_field(&mut extra, "chunk_count", "2");
    extra.insert(chunks[0] + 1, rewrite_chunk_index(&original[chunks[0]], 1));
    verify_backup_rejects(bytes_from_lines(&extra), "extra");
}

#[test]
fn chunked_backup_rejects_reordered_chunks_and_cross_backup_splice() {
    let backup_a = large_backup("target/hydra-msg-test-storage-chunk-large-a");
    let backup_b = large_backup("target/hydra-msg-test-storage-chunk-large-b");
    let original = lines(&backup_a);
    let other = lines(&backup_b);
    let chunks = chunk_indices(&original);
    let other_chunks = chunk_indices(&other);
    assert!(chunks.len() > 1);
    assert_eq!(chunks.len(), other_chunks.len());

    let mut reordered = original.clone();
    reordered.swap(chunks[0], chunks[1]);
    verify_backup_rejects(bytes_from_lines(&reordered), "reordered");

    let mut spliced = original.clone();
    spliced[chunks[0]] = other[other_chunks[0]].clone();
    verify_backup_rejects(bytes_from_lines(&spliced), "cross-backup-splice");
}

#[test]
fn state_and_backup_chunks_are_not_interchangeable() {
    let state_path = "target/hydra-msg-test-storage-chunk-state-source";
    let mut hydra = fresh(state_path);
    hydra.generate_id("id-pw").unwrap();
    let backup = hydra.export_backup("backup-pw").unwrap();
    drop(hydra);

    let state = state_bytes(state_path);
    let state_lines = lines(&state);
    let backup_lines = lines(&backup);
    let state_chunk = chunk_indices(&state_lines)[0];
    let backup_chunk = chunk_indices(&backup_lines)[0];

    let mut backup_with_state_chunk = backup_lines.clone();
    backup_with_state_chunk[backup_chunk] = state_lines[state_chunk].clone();
    verify_backup_rejects(
        bytes_from_lines(&backup_with_state_chunk),
        "state-chunk-in-backup",
    );

    let mut state_with_backup_chunk = state_lines.clone();
    state_with_backup_chunk[state_chunk] = backup_lines[backup_chunk].clone();
    let state_file = Path::new(state_path).join(STATE_FILE_NAME);
    fs::write(&state_file, bytes_from_lines(&state_with_backup_chunk)).unwrap();
    assert!(Hydra::open(state_path, "state-pw").is_err());
}
