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

fn deterministic_kdf() -> PasswordKdfRecord {
    PasswordKdfRecord::with_salt("mobile", [0x44; 32]).unwrap()
}

fn state_fixture() -> (SecretBytes<32>, Vec<u8>) {
    let key = SecretBytes::from_array([0x55; 32]);
    let envelope =
        encode_encrypted_state(b"fixture", &key, &deterministic_kdf(), [0x66; 12]).unwrap();
    (key, envelope)
}

#[test]
fn storage_parser_rejects_version_size_nonce_chunk_and_trailing_errors() {
    let (key, envelope) = state_fixture();
    let text = String::from_utf8(envelope).unwrap();

    let future_version = text.replace("format_version\t1", "format_version\t2");
    assert_eq!(
        decode_encrypted_state(future_version.as_bytes(), &key),
        Err(HydraMsgError::Unsupported("storage format version"))
    );

    let wrong_chunk_size = text.replace(
        &format!("chunk_size\t{STORAGE_CHUNK_PLAINTEXT_BYTES}"),
        "chunk_size\t1",
    );
    assert_eq!(
        decode_encrypted_state(wrong_chunk_size.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("storage chunk size"))
    );

    let nonce_line = text
        .lines()
        .find(|line| line.starts_with("nonce\t"))
        .unwrap();
    let short_nonce = text.replace(nonce_line, "nonce\t00");
    assert_eq!(
        decode_encrypted_state(short_nonce.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("storage nonce"))
    );
    let non_hex_nonce = text.replace(nonce_line, "nonce\tzzzzzzzzzzzzzzzzzzzzzzzz");
    assert_eq!(
        decode_encrypted_state(non_hex_nonce.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("hex character"))
    );

    let wrong_chunk_label = text.replacen("chunk\t0\t", "record\t0\t", 1);
    assert_eq!(
        decode_encrypted_state(wrong_chunk_label.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("storage chunk"))
    );

    let chunk_line = text
        .lines()
        .find(|line| line.starts_with("chunk\t"))
        .unwrap();
    let extra_chunk_column = text.replace(chunk_line, &format!("{chunk_line}\textra"));
    assert_eq!(
        decode_encrypted_state(extra_chunk_column.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("storage chunk"))
    );

    let without_chunk = text
        .lines()
        .filter(|line| !line.starts_with("chunk\t"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        decode_encrypted_state(without_chunk.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("storage chunk"))
    );

    let mut trailing = text.clone();
    trailing.push_str("unexpected\tdata\n");
    assert_eq!(
        decode_encrypted_state(trailing.as_bytes(), &key),
        Err(HydraMsgError::InvalidEncoding("storage trailing data"))
    );
}

#[test]
fn storage_parser_rejects_wrong_record_type_missing_fields_and_magic_line() {
    let (key, envelope) = state_fixture();
    let text = String::from_utf8(envelope).unwrap();

    let missing_version = text
        .lines()
        .filter(|line| !line.starts_with("format_version\t"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(decode_encrypted_state(missing_version.as_bytes(), &key).is_err());

    let backup = encode_chunked_storage(
        b"fixture",
        BACKUP_MAGIC,
        &key,
        &deterministic_kdf(),
        [0x77; 12],
        MAX_BACKUP_BYTES,
        "backup",
    )
    .unwrap();
    assert_eq!(
        decode_encrypted_state(&backup, &key),
        Err(HydraMsgError::InvalidEncoding("storage magic"))
    );

    assert_eq!(
        parse_chunked_storage(b"HYDRA-WRONG\n", b"HYDRA", 1024, "test"),
        Err(HydraMsgError::InvalidEncoding("storage magic line"))
    );
}

#[test]
fn storage_plaintext_and_envelope_boundaries_are_enforced() {
    assert_eq!(
        unpack_storage_plaintext(&[]),
        Err(HydraMsgError::InvalidEncoding("storage plaintext size"))
    );
    assert_eq!(
        unpack_storage_plaintext(&[0]),
        Err(HydraMsgError::InvalidEncoding("storage plaintext size"))
    );
    assert_eq!(
        decode_chunked_storage(
            &SecretBytes::from_array([1; 32]),
            "aad",
            [0; 12],
            STORAGE_CHUNK_PLAINTEXT_BYTES - 1,
            &[],
            "test",
        ),
        Err(HydraMsgError::InvalidEncoding("storage chunk size"))
    );
    assert_eq!(
        reject_oversize_envelope(b"too long", 1, "oversize"),
        Err(HydraMsgError::InvalidEncoding("oversize"))
    );
    assert_eq!(
        reject_long_envelope_lines("short\nlong-line", 5, "line size"),
        Err(HydraMsgError::InvalidEncoding("line size"))
    );

    let snapshot_len = STORAGE_CHUNK_PLAINTEXT_BYTES - STORAGE_PLAINTEXT_MAGIC.len() - 8;
    let key = SecretBytes::from_array([0x88; 32]);
    let kdf = deterministic_kdf();
    for expected_chunks in [1_usize, 2] {
        let snapshot = vec![0xa5; snapshot_len + expected_chunks - 1];
        let envelope =
            encode_encrypted_state(&snapshot, &key, &kdf, [expected_chunks as u8; 12]).unwrap();
        let text = std::str::from_utf8(&envelope).unwrap();
        assert!(text.contains(&format!("chunk_count\t{expected_chunks}")));
        assert_eq!(decode_encrypted_state(&envelope, &key), Ok(snapshot));
    }
}
