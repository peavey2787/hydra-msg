use super::{
    decode_kdf_fields, derive_password_key, encode_kdf_fields, exact_array_from_vec, hex_decode,
    hex_encode, required_field, write_u64, BytesReader, PasswordKdfRecord,
};
use crate::{
    limits::{
        reject_encoded_size, reject_input_size, MAX_BACKUP_BYTES, MAX_ENCRYPTED_STATE_BYTES,
        MAX_STATE_SNAPSHOT_BYTES,
    },
    HydraMsgError, HydraResult, BACKUP_MAGIC, STATE_MAGIC,
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes};

const STATE_KEY_LABEL: &[u8] = b"HYDRA-MSG/facade/state-key";
const BACKUP_KEY_LABEL: &[u8] = b"HYDRA-MSG/facade/backup-key";
const STORAGE_PLAINTEXT_MAGIC: &[u8] = b"HYDRA-MSG-STORAGE-PLAINTEXT\n";
const STORAGE_CHUNK_PLAINTEXT_BYTES: usize = 64 * 1024;
const STORAGE_FORMAT_VERSION: u8 = 1;

pub(crate) fn new_storage_kdf() -> HydraResult<PasswordKdfRecord> {
    PasswordKdfRecord::new_interactive()
}

pub(crate) fn state_key(password: &str, kdf: &PasswordKdfRecord) -> HydraResult<SecretBytes<32>> {
    derive_password_key(STATE_KEY_LABEL, password, kdf)
}

pub(crate) fn backup_key(password: &str, kdf: &PasswordKdfRecord) -> HydraResult<SecretBytes<32>> {
    derive_password_key(BACKUP_KEY_LABEL, password, kdf)
}

pub(crate) fn encode_backup(
    snapshot: &[u8],
    password: &str,
    kdf: &PasswordKdfRecord,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    reject_input_size(
        snapshot.len(),
        MAX_STATE_SNAPSHOT_BYTES,
        "backup snapshot size",
    )?;
    let key = backup_key(password, kdf)?;
    encode_chunked_storage(
        snapshot,
        BACKUP_MAGIC,
        &key,
        kdf,
        nonce,
        MAX_BACKUP_BYTES,
        "backup",
    )
}

pub(crate) fn decode_backup(bytes: &[u8], password: &str) -> HydraResult<Vec<u8>> {
    let (aad, kdf, nonce, chunk_size, chunks) =
        parse_chunked_storage(bytes, BACKUP_MAGIC, MAX_BACKUP_BYTES, "backup")?;
    let key = backup_key(password, &kdf)?;
    decode_chunked_storage(&key, &aad, nonce, chunk_size, &chunks, "backup")
}

pub(crate) fn encode_encrypted_state(
    snapshot: &[u8],
    key: &SecretBytes<32>,
    kdf: &PasswordKdfRecord,
    nonce: [u8; 12],
) -> HydraResult<Vec<u8>> {
    reject_input_size(
        snapshot.len(),
        MAX_STATE_SNAPSHOT_BYTES,
        "state snapshot size",
    )?;
    encode_chunked_storage(
        snapshot,
        STATE_MAGIC,
        key,
        kdf,
        nonce,
        MAX_ENCRYPTED_STATE_BYTES,
        "state",
    )
}

pub(crate) fn decode_encrypted_state(bytes: &[u8], key: &SecretBytes<32>) -> HydraResult<Vec<u8>> {
    let (aad, _, nonce, chunk_size, chunks) =
        parse_chunked_storage(bytes, STATE_MAGIC, MAX_ENCRYPTED_STATE_BYTES, "state")?;
    decode_chunked_storage(key, &aad, nonce, chunk_size, &chunks, "state")
}

pub(crate) fn parse_state_kdf(bytes: &[u8]) -> HydraResult<PasswordKdfRecord> {
    let (_, kdf, _, _, _) =
        parse_chunked_storage(bytes, STATE_MAGIC, MAX_ENCRYPTED_STATE_BYTES, "state")?;
    Ok(kdf)
}

fn encode_chunked_storage(
    snapshot: &[u8],
    magic: &[u8],
    key: &SecretBytes<32>,
    kdf: &PasswordKdfRecord,
    base_nonce: [u8; 12],
    max_envelope_bytes: usize,
    _description: &'static str,
) -> HydraResult<Vec<u8>> {
    let plaintext = pack_storage_plaintext(snapshot)?;
    let chunk_count = plaintext
        .len()
        .div_ceil(STORAGE_CHUNK_PLAINTEXT_BYTES)
        .max(1);
    reject_chunk_count(chunk_count)?;
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
        let end = plaintext.len().min(start + STORAGE_CHUNK_PLAINTEXT_BYTES);
        let chunk = &plaintext[start..end];
        if chunk.len() != STORAGE_CHUNK_PLAINTEXT_BYTES {
            return Err(HydraMsgError::InvalidEncoding("storage chunk size"));
        }
        let nonce = chunk_nonce(base_nonce, index)?;
        let chunk_aad = chunk_aad(&aad, index);
        let ciphertext = RustCryptoBackend::aead_seal(key, &nonce, chunk_aad.as_bytes(), chunk)?;
        out.extend_from_slice(b"chunk\t");
        out.extend_from_slice(index.to_string().as_bytes());
        out.push(b'\t');
        out.extend_from_slice(hex_encode(&ciphertext).as_bytes());
        out.push(b'\n');
    }
    reject_input_size(out.len(), max_envelope_bytes, "storage size")?;
    Ok(out)
}

fn decode_chunked_storage(
    key: &SecretBytes<32>,
    aad: &str,
    base_nonce: [u8; 12],
    chunk_size: usize,
    chunks: &[Vec<u8>],
    _description: &'static str,
) -> HydraResult<Vec<u8>> {
    if chunk_size != STORAGE_CHUNK_PLAINTEXT_BYTES {
        return Err(HydraMsgError::InvalidEncoding("storage chunk size"));
    }
    let mut plaintext = Vec::with_capacity(
        chunks
            .len()
            .checked_mul(chunk_size)
            .ok_or(HydraMsgError::InvalidEncoding("storage chunk count"))?,
    );
    for (index, ciphertext) in chunks.iter().enumerate() {
        if ciphertext.len() != chunk_size + hydra_core::AEAD_TAG_SIZE {
            return Err(HydraMsgError::InvalidEncoding(
                "storage chunk ciphertext size",
            ));
        }
        let nonce = chunk_nonce(base_nonce, index)?;
        let chunk_aad = chunk_aad(aad, index);
        let chunk = RustCryptoBackend::aead_open(key, &nonce, chunk_aad.as_bytes(), ciphertext)?;
        if chunk.len() != chunk_size {
            return Err(HydraMsgError::InvalidEncoding(
                "storage chunk plaintext size",
            ));
        }
        plaintext.extend_from_slice(&chunk);
    }
    let snapshot = unpack_storage_plaintext(&plaintext)?;
    reject_encoded_size(
        snapshot.len(),
        MAX_STATE_SNAPSHOT_BYTES,
        "storage snapshot size",
    )?;
    Ok(snapshot)
}

fn pack_storage_plaintext(snapshot: &[u8]) -> HydraResult<Vec<u8>> {
    let mut out = Vec::with_capacity(
        STORAGE_PLAINTEXT_MAGIC
            .len()
            .checked_add(8)
            .and_then(|len| len.checked_add(snapshot.len()))
            .ok_or(HydraMsgError::InvalidInput("state snapshot size"))?,
    );
    out.extend_from_slice(STORAGE_PLAINTEXT_MAGIC);
    write_u64(&mut out, snapshot.len() as u64);
    out.extend_from_slice(snapshot);
    let padded_len =
        out.len().div_ceil(STORAGE_CHUNK_PLAINTEXT_BYTES) * STORAGE_CHUNK_PLAINTEXT_BYTES;
    out.resize(padded_len, 0);
    Ok(out)
}

fn unpack_storage_plaintext(bytes: &[u8]) -> HydraResult<Vec<u8>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(STORAGE_CHUNK_PLAINTEXT_BYTES) {
        return Err(HydraMsgError::InvalidEncoding("storage plaintext size"));
    }
    let mut reader = BytesReader::new(bytes);
    reader.expect(STORAGE_PLAINTEXT_MAGIC)?;
    let snapshot_len = reader.read_u64()? as usize;
    reject_encoded_size(
        snapshot_len,
        MAX_STATE_SNAPSHOT_BYTES,
        "state snapshot size",
    )?;
    let snapshot = reader.read_vec(snapshot_len)?;
    let consumed = STORAGE_PLAINTEXT_MAGIC
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(snapshot_len))
        .ok_or(HydraMsgError::InvalidEncoding("storage plaintext size"))?;
    let remaining = bytes
        .len()
        .checked_sub(consumed)
        .ok_or(HydraMsgError::InvalidEncoding("storage plaintext size"))?;
    if !reader.read(remaining)?.iter().all(|byte| *byte == 0) {
        return Err(HydraMsgError::InvalidEncoding("storage padding"));
    }
    Ok(snapshot)
}

type ParsedStorage = (String, PasswordKdfRecord, [u8; 12], usize, Vec<Vec<u8>>);

fn parse_chunked_storage(
    bytes: &[u8],
    magic: &[u8],
    max_bytes: usize,
    _description: &'static str,
) -> HydraResult<ParsedStorage> {
    reject_oversize_envelope(bytes, max_bytes, "storage size")?;
    if !bytes.starts_with(magic) {
        return Err(HydraMsgError::InvalidEncoding("storage magic"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| HydraMsgError::InvalidEncoding("storage utf-8"))?;
    reject_long_envelope_lines(text, max_bytes, "storage line length")?;
    let mut lines = text.lines();
    let expected_magic = std::str::from_utf8(magic).unwrap_or_default().trim_end();
    let magic_line = lines
        .next()
        .ok_or(HydraMsgError::InvalidEncoding("storage magic line"))?;
    if magic_line != expected_magic {
        return Err(HydraMsgError::InvalidEncoding("storage magic line"));
    }
    let kdf = decode_kdf_fields(&mut lines)?;
    let version = required_field(&mut lines, "format_version", "storage format version")?
        .parse::<u8>()
        .map_err(|_| HydraMsgError::InvalidEncoding("storage format version"))?;
    if version != STORAGE_FORMAT_VERSION {
        return Err(HydraMsgError::Unsupported("storage format version"));
    }
    let chunk_size = required_field(&mut lines, "chunk_size", "storage chunk size")?
        .parse::<usize>()
        .map_err(|_| HydraMsgError::InvalidEncoding("storage chunk size"))?;
    if chunk_size != STORAGE_CHUNK_PLAINTEXT_BYTES {
        return Err(HydraMsgError::InvalidEncoding("storage chunk size"));
    }
    let chunk_count = required_field(&mut lines, "chunk_count", "storage chunk count")?
        .parse::<usize>()
        .map_err(|_| HydraMsgError::InvalidEncoding("storage chunk count"))?;
    reject_chunk_count(chunk_count)?;
    let nonce_hex = required_field(&mut lines, "nonce", "storage nonce")?;
    if nonce_hex.len() != 24 {
        return Err(HydraMsgError::InvalidEncoding("storage nonce"));
    }
    let nonce = exact_array_from_vec(hex_decode(nonce_hex)?)?;
    let aad = storage_aad(magic, &kdf, chunk_size, chunk_count, nonce_hex);
    let mut chunks = Vec::with_capacity(chunk_count);
    for expected_index in 0..chunk_count {
        let line = lines
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("storage chunk"))?;
        let mut parts = line.split('\t');
        if parts.next() != Some("chunk") {
            return Err(HydraMsgError::InvalidEncoding("storage chunk"));
        }
        let got_index = parts
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("storage chunk index"))?
            .parse::<usize>()
            .map_err(|_| HydraMsgError::InvalidEncoding("storage chunk index"))?;
        if got_index != expected_index {
            return Err(HydraMsgError::InvalidEncoding("storage chunk index"));
        }
        let ciphertext_hex = parts
            .next()
            .ok_or(HydraMsgError::InvalidEncoding("storage chunk ciphertext"))?;
        if parts.next().is_some() {
            return Err(HydraMsgError::InvalidEncoding("storage chunk"));
        }
        reject_encoded_size(
            ciphertext_hex.len(),
            (chunk_size + hydra_core::AEAD_TAG_SIZE) * 2,
            "storage chunk ciphertext size",
        )?;
        let ciphertext = hex_decode(ciphertext_hex)?;
        chunks.push(ciphertext);
    }
    reject_trailing_nonempty_lines(&mut lines, "storage trailing data")?;
    Ok((aad, kdf, nonce, chunk_size, chunks))
}

fn storage_aad(
    magic: &[u8],
    kdf: &PasswordKdfRecord,
    chunk_size: usize,
    chunk_count: usize,
    nonce_hex: &str,
) -> String {
    format!(
        "{}{}format_version\t{}\nchunk_size\t{}\nchunk_count\t{}\nnonce\t{}\n",
        std::str::from_utf8(magic).unwrap_or_default(),
        encode_kdf_fields(kdf),
        STORAGE_FORMAT_VERSION,
        chunk_size,
        chunk_count,
        nonce_hex
    )
}

fn chunk_aad(header_aad: &str, index: usize) -> String {
    format!("{header_aad}chunk_index\t{index}\n")
}

fn chunk_nonce(base_nonce: [u8; 12], index: usize) -> HydraResult<[u8; 12]> {
    let index =
        u32::try_from(index).map_err(|_| HydraMsgError::InvalidEncoding("storage chunk index"))?;
    let mut nonce = base_nonce;
    nonce[8..12].copy_from_slice(&index.to_be_bytes());
    Ok(nonce)
}

fn reject_chunk_count(chunk_count: usize) -> HydraResult<()> {
    let max_packed = STORAGE_PLAINTEXT_MAGIC
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(MAX_STATE_SNAPSHOT_BYTES))
        .ok_or(HydraMsgError::InvalidEncoding("storage snapshot size"))?;
    let max_chunks = max_packed.div_ceil(STORAGE_CHUNK_PLAINTEXT_BYTES).max(1);
    if chunk_count == 0 || chunk_count > max_chunks {
        return Err(HydraMsgError::InvalidEncoding("storage chunk count"));
    }
    Ok(())
}

fn reject_oversize_envelope(
    bytes: &[u8],
    max: usize,
    description: &'static str,
) -> HydraResult<()> {
    if bytes.len() > max {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

fn reject_long_envelope_lines(
    text: &str,
    max: usize,
    description: &'static str,
) -> HydraResult<()> {
    for line in text.lines() {
        if line.len() > max {
            return Err(HydraMsgError::InvalidEncoding(description));
        }
    }
    Ok(())
}

fn reject_trailing_nonempty_lines<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    description: &'static str,
) -> HydraResult<()> {
    if lines.any(|line| !line.trim().is_empty()) {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
