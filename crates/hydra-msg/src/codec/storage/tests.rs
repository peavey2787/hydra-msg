use super::*;

fn encode_plaintext_for_test(
    magic: &[u8],
    key: &SecretBytes<32>,
    kdf: &PasswordKdfRecord,
    base_nonce: [u8; 12],
    plaintext: &[u8],
) -> Vec<u8> {
    assert!(!plaintext.is_empty());
    assert!(plaintext
        .len()
        .is_multiple_of(STORAGE_CHUNK_PLAINTEXT_BYTES));
    let chunk_count = plaintext.len() / STORAGE_CHUNK_PLAINTEXT_BYTES;
    let nonce_hex = hex_encode(&base_nonce);
    let aad = storage_aad(
        magic,
        kdf,
        STORAGE_CHUNK_PLAINTEXT_BYTES,
        chunk_count,
        &nonce_hex,
    );
    let mut out = aad.clone().into_bytes();
    for index in 0..chunk_count {
        let start = index * STORAGE_CHUNK_PLAINTEXT_BYTES;
        let end = start + STORAGE_CHUNK_PLAINTEXT_BYTES;
        let nonce = chunk_nonce(base_nonce, index).unwrap();
        let chunk_aad = chunk_aad(&aad, index);
        let ciphertext =
            RustCryptoBackend::aead_seal(key, &nonce, chunk_aad.as_bytes(), &plaintext[start..end])
                .unwrap();
        out.extend_from_slice(b"chunk\t");
        out.extend_from_slice(index.to_string().as_bytes());
        out.push(b'\t');
        out.extend_from_slice(hex_encode(&ciphertext).as_bytes());
        out.push(b'\n');
    }
    out
}

#[test]
fn validly_encrypted_storage_rejects_wrong_final_padding() {
    let key = SecretBytes::from_array([7; 32]);
    let kdf = new_storage_kdf().unwrap();
    let mut plaintext = vec![0_u8; STORAGE_CHUNK_PLAINTEXT_BYTES];
    let mut header = Vec::new();
    header.extend_from_slice(STORAGE_PLAINTEXT_MAGIC);
    write_u64(&mut header, 0);
    plaintext[..header.len()].copy_from_slice(&header);
    plaintext[header.len()] = 1;

    let envelope = encode_plaintext_for_test(STATE_MAGIC, &key, &kdf, [1; 12], &plaintext);
    assert_eq!(
        decode_encrypted_state(&envelope, &key),
        Err(HydraMsgError::InvalidEncoding("storage padding"))
    );
}

#[test]
fn validly_encrypted_storage_rejects_wrong_snapshot_length() {
    let key = SecretBytes::from_array([8; 32]);
    let kdf = new_storage_kdf().unwrap();
    let mut plaintext = vec![0_u8; STORAGE_CHUNK_PLAINTEXT_BYTES];
    let mut header = Vec::new();
    header.extend_from_slice(STORAGE_PLAINTEXT_MAGIC);
    write_u64(&mut header, (MAX_STATE_SNAPSHOT_BYTES + 1) as u64);
    plaintext[..header.len()].copy_from_slice(&header);

    let envelope = encode_plaintext_for_test(STATE_MAGIC, &key, &kdf, [2; 12], &plaintext);
    assert_eq!(
        decode_encrypted_state(&envelope, &key),
        Err(HydraMsgError::InvalidEncoding("state snapshot size"))
    );
}

#[test]
fn valid_chunks_under_wrong_aad_are_rejected() {
    let key = SecretBytes::from_array([9; 32]);
    let kdf = new_storage_kdf().unwrap();
    let snapshot = b"HYDRA-MSG-STATE-SNAPSHOT\nstate_generation\t0\nnext_message_id\t1\n";
    let state = encode_encrypted_state(snapshot, &key, &kdf, [3; 12]).unwrap();
    let backup_like = encode_chunked_storage(
        snapshot,
        BACKUP_MAGIC,
        &key,
        &kdf,
        [3; 12],
        MAX_BACKUP_BYTES,
        "backup",
    )
    .unwrap();

    let mut state_lines = std::str::from_utf8(&state)
        .unwrap()
        .lines()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let backup_chunk = std::str::from_utf8(&backup_like)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("chunk\t"))
        .unwrap()
        .to_owned();
    let state_chunk = state_lines
        .iter()
        .position(|line| line.starts_with("chunk\t"))
        .unwrap();
    state_lines[state_chunk] = backup_chunk;
    let mut spliced = state_lines.join("\n").into_bytes();
    spliced.push(b'\n');

    assert!(decode_encrypted_state(&spliced, &key).is_err());
}

#[test]
fn chunk_count_boundary_rejects_zero_and_above_snapshot_capacity() {
    let key = SecretBytes::from_array([10; 32]);
    let kdf = new_storage_kdf().unwrap();
    let valid = encode_encrypted_state(b"small", &key, &kdf, [4; 12]).unwrap();
    let valid_text = std::str::from_utf8(&valid).unwrap();
    let max_packed = STORAGE_PLAINTEXT_MAGIC.len() + 8 + MAX_STATE_SNAPSHOT_BYTES;
    let max_chunks = max_packed.div_ceil(STORAGE_CHUNK_PLAINTEXT_BYTES).max(1);

    let zero = valid_text.replace("chunk_count\t1", "chunk_count\t0");
    assert!(decode_encrypted_state(zero.as_bytes(), &key).is_err());

    let too_many = valid_text.replace(
        "chunk_count\t1",
        &format!("chunk_count\t{}", max_chunks + 1),
    );
    assert!(decode_encrypted_state(too_many.as_bytes(), &key).is_err());
}
