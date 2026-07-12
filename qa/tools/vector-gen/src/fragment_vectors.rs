use super::{VectorMetadata, tv_draw, write_bytes, write_metadata};
use std::{fs, path::Path};

const FRAGMENT_MAGIC: &[u8] = b"HYDRA-MSG-FRAGMENT\n";
const MAX_FRAGMENTS_PER_MESSAGE: u32 = 16_384;

fn encode_record(
    kind: u8,
    lobby_id: Option<&[u8; 32]>,
    fragment_id: &[u8; 32],
    total: u32,
    index: u32,
    bytes: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(FRAGMENT_MAGIC);
    output.push(kind);
    if let Some(lobby_id) = lobby_id {
        output.extend_from_slice(lobby_id);
    }
    output.extend_from_slice(fragment_id);
    output.extend_from_slice(&total.to_be_bytes());
    output.extend_from_slice(&index.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("fragment fixture length fits u32")
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    output
}

fn write_vector(
    root: &Path,
    vector_id: &str,
    metadata: &VectorMetadata<'_>,
    artifacts: &[(&str, &[u8])],
) {
    let directory = root.join("fragment").join(vector_id);
    fs::create_dir_all(&directory).expect("create fragment vector directory");
    for (name, bytes) in artifacts {
        write_bytes(&directory, name, bytes);
    }
    write_metadata(&directory, vector_id, metadata, artifacts);
}

fn generate_direct(root: &Path) {
    const ID: &str = "TV-FRAG-DIRECT-000";
    let fragment_id: [u8; 32] = tv_draw(ID, "fragment-id", 0, 32)
        .try_into()
        .expect("fragment ID length");
    let payload = b"HYDRA fragment vector payload";
    let part_0 = encode_record(1, None, &fragment_id, 3, 0, b"HYDRA fragment ");
    let part_1 = encode_record(1, None, &fragment_id, 3, 1, b"vector ");
    let part_2 = encode_record(1, None, &fragment_id, 3, 2, b"payload");
    let artifacts: [(&str, &[u8]); 5] = [
        ("fragment_id", &fragment_id),
        ("payload", payload),
        ("part_0", &part_0),
        ("part_1", &part_1),
        ("part_2", &part_2),
    ];
    write_vector(
        root,
        ID,
        &VectorMetadata {
            backend: "independent canonical fragment encoder in hydra-vector-gen",
            result: "three direct fragment records decode and reassemble in index order",
            expected_state: "one incomplete message becomes one complete direct payload",
            cleanup: "all pending fragment parts removed after complete reassembly",
            entropy: &[("fragment-id", 0, 32, "fragment_id")],
        },
        &artifacts,
    );
}

fn generate_lobby(root: &Path) {
    const ID: &str = "TV-FRAG-LOBBY-000";
    let fragment_id: [u8; 32] = tv_draw(ID, "fragment-id", 0, 32)
        .try_into()
        .expect("fragment ID length");
    let lobby_id: [u8; 32] = tv_draw(ID, "lobby-id", 0, 32)
        .try_into()
        .expect("lobby ID length");
    let payload = b"lobby-scoped-fragment";
    let part_0 = encode_record(3, Some(&lobby_id), &fragment_id, 2, 0, b"lobby-scoped-");
    let part_1 = encode_record(3, Some(&lobby_id), &fragment_id, 2, 1, b"fragment");
    let artifacts: [(&str, &[u8]); 5] = [
        ("fragment_id", &fragment_id),
        ("lobby_id", &lobby_id),
        ("payload", payload),
        ("part_0", &part_0),
        ("part_1", &part_1),
    ];
    write_vector(
        root,
        ID,
        &VectorMetadata {
            backend: "independent canonical fragment encoder in hydra-vector-gen",
            result: "two lobby fragment records retain the same explicit lobby scope",
            expected_state: "reassembly key is bound to lobby ID and fragment ID",
            cleanup: "all pending lobby fragment parts removed after complete reassembly",
            entropy: &[
                ("fragment-id", 0, 32, "fragment_id"),
                ("lobby-id", 0, 32, "lobby_id"),
            ],
        },
        &artifacts,
    );
}

fn generate_negative(root: &Path) {
    const ID: &str = "TV-FRAG-BAD-000";
    let fragment_id: [u8; 32] = tv_draw(ID, "fragment-id", 0, 32)
        .try_into()
        .expect("fragment ID length");
    let zero_total = encode_record(1, None, &fragment_id, 0, 0, b"x");
    let index_equal_total = encode_record(1, None, &fragment_id, 1, 1, b"x");
    let total_over_limit = encode_record(
        1,
        None,
        &fragment_id,
        MAX_FRAGMENTS_PER_MESSAGE + 1,
        0,
        b"x",
    );
    let unknown_kind = encode_record(0xff, None, &fragment_id, 1, 0, b"x");
    let mut trailing_bytes = encode_record(1, None, &fragment_id, 1, 0, b"x");
    trailing_bytes.push(0xff);
    let mut declared_length_overrun = encode_record(1, None, &fragment_id, 1, 0, b"x");
    let length_offset = FRAGMENT_MAGIC.len() + 1 + 32 + 4 + 4;
    declared_length_overrun[length_offset..length_offset + 4].copy_from_slice(&2_u32.to_be_bytes());
    let artifacts: [(&str, &[u8]); 7] = [
        ("fragment_id", &fragment_id),
        ("zero_total", &zero_total),
        ("index_equal_total", &index_equal_total),
        ("total_over_limit", &total_over_limit),
        ("unknown_kind", &unknown_kind),
        ("trailing_bytes", &trailing_bytes),
        ("declared_length_overrun", &declared_length_overrun),
    ];
    write_vector(
        root,
        ID,
        &VectorMetadata {
            backend: "independent canonical fragment encoder in hydra-vector-gen",
            result: "every malformed fragment record is rejected before reassembly state mutation",
            expected_state: "no pending fragment entry is created",
            cleanup: "no attacker-controlled fragment bytes retained",
            entropy: &[("fragment-id", 0, 32, "fragment_id")],
        },
        &artifacts,
    );
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "read fragment vector directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let path = entry
            .map_err(|error| format!("read fragment vector entry: {error}"))?
            .path();
        if path.is_dir() {
            collect_files(root, &path, output)?;
        } else {
            output.push(
                path.strip_prefix(root)
                    .map_err(|_| format!("fragment path outside root: {}", path.display()))?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn compare_generated(expected_root: &Path, actual_root: &Path) -> Result<(), String> {
    let expected_fragment = expected_root.join("fragment");
    let actual_fragment = actual_root.join("fragment");
    let mut expected_files = Vec::new();
    let mut actual_files = Vec::new();
    collect_files(&expected_fragment, &expected_fragment, &mut expected_files)?;
    collect_files(&actual_fragment, &actual_fragment, &mut actual_files)?;
    expected_files.sort();
    actual_files.sort();
    if expected_files != actual_files {
        return Err(format!(
            "fragment vector inventory mismatch; expected={:?} actual={:?}",
            expected_files, actual_files
        ));
    }
    for relative in expected_files {
        let expected = fs::read(expected_fragment.join(&relative))
            .map_err(|error| format!("read generated fragment {relative}: {error}"))?;
        let actual = fs::read(actual_fragment.join(&relative))
            .map_err(|error| format!("read committed fragment {relative}: {error}"))?;
        if expected != actual {
            return Err(format!(
                "fragment vector differs from generator: {relative}"
            ));
        }
    }
    Ok(())
}

pub fn verify(root: &Path) -> Result<(), String> {
    let temporary =
        std::env::temp_dir().join(format!("hydra-fragment-vectors-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary)
            .map_err(|error| format!("remove stale fragment vector temp directory: {error}"))?;
    }
    fs::create_dir_all(&temporary)
        .map_err(|error| format!("create fragment vector temp directory: {error}"))?;
    generate(&temporary);
    let result = compare_generated(&temporary, root);
    fs::remove_dir_all(&temporary)
        .map_err(|error| format!("remove fragment vector temp directory: {error}"))?;
    result
}

pub fn generate(root: &Path) {
    generate_direct(root);
    generate_lobby(root);
    generate_negative(root);
}
