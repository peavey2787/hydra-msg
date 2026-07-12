use std::{collections::BTreeSet, fs, path::Path};

const EXPECTED_VECTOR_DIRECTORIES: &[&str] = &[
    "envelope/TV-HDR-000",
    "fragment/TV-FRAG-BAD-000",
    "fragment/TV-FRAG-DIRECT-000",
    "fragment/TV-FRAG-LOBBY-000",
    "group/TV-GROUP-BAD-000",
    "group/TV-GROUP-CREATE-000",
    "group/TV-GROUP-JOIN-000",
    "group/TV-GROUP-JOIN-BROADCAST-000",
    "group/TV-GROUP-JOIN-INTERACTIVE-000",
    "group/TV-GROUP-JOIN-LITE-000",
    "group/TV-GROUP-LEAVE-LITE-000",
    "group/TV-GROUP-MODE-BAD-000",
    "group/TV-GROUP-MODE-INTERACTIVE-BROADCAST-000",
    "group/TV-GROUP-MODE-INTERACTIVE-LITE-000",
    "group/TV-GROUP-MODE-LITE-INTERACTIVE-000",
    "group/TV-GROUP-MSG-BAD-000",
    "group/TV-GROUP-MSG-BROADCAST-FULL-000",
    "group/TV-GROUP-MSG-BROADCAST-LITE-000",
    "group/TV-GROUP-MSG-BROADCAST-STANDARD-000",
    "group/TV-GROUP-MSG-INTERACTIVE-FULL-000",
    "group/TV-GROUP-MSG-INTERACTIVE-STANDARD-000",
    "group/TV-GROUP-MSG-LITE-MAX-000",
    "group/TV-GROUP-MSG-REORDER-000",
    "group/TV-GROUP-NEG-BROADCAST-SENDERS-OVER-16-000",
    "group/TV-GROUP-NEG-DUP-ACTIVE-FINGERPRINT-000",
    "group/TV-GROUP-NEG-DUP-MEMBER-ID-000",
    "group/TV-GROUP-NEG-FORK-CONFLICT-000",
    "group/TV-GROUP-NEG-FULL-APP-143968-000",
    "group/TV-GROUP-NEG-GOV-THRESHOLD-OVER-COUNT-000",
    "group/TV-GROUP-NEG-GOV-THRESHOLD-ZERO-000",
    "group/TV-GROUP-NEG-INVALID-ACTIVE-ROLE-000",
    "group/TV-GROUP-NEG-LITE-APP-608-000",
    "group/TV-GROUP-NEG-LITE-ATTACHMENT-000",
    "group/TV-GROUP-NEG-ROSTER-OVER-MAX-000",
    "group/TV-GROUP-NEG-SIG-COUNT-18-000",
    "group/TV-GROUP-NEG-SIG-COUNT-ZERO-000",
    "group/TV-GROUP-NEG-SIG-DUPLICATE-000",
    "group/TV-GROUP-NEG-SIG-OUT-OF-ORDER-000",
    "group/TV-GROUP-NEG-WRONG-CONFIRMATION-TAG-000",
    "group/TV-GROUP-NEG-WRONG-NEW-EPOCH-STATE-000",
    "group/TV-GROUP-NEG-WRONG-OLD-EPOCH-STATE-000",
    "group/TV-GROUP-NEG-WRONG-PARENT-COMMIT-HASH-000",
    "group/TV-GROUP-NEG-WRONG-ROSTER-HASH-000",
    "group/TV-GROUP-NEG-WRONG-TREE-HASH-000",
    "group/TV-GROUP-NEG-WRONG-UPDATE-PATH-HASH-000",
    "group/TV-GROUP-NEG-WRONG-WELCOME-RECIPIENT-000",
    "group/TV-GROUP-REMOVE-BROADCAST-000",
    "group/TV-GROUP-REMOVE-INTERACTIVE-000",
    "group/TV-GROUP-REMOVE-LITE-000",
    "group/TV-GROUP-ROLE-BROADCAST-000",
    "group/TV-GROUP-ROLE-INTERACTIVE-000",
    "group/TV-GROUP-ROLE-LITE-000",
    "group/TV-GROUP-SELF-UPDATE-BROADCAST-000",
    "group/TV-GROUP-SELF-UPDATE-INTERACTIVE-000",
    "handshake/TV-HS-TAMPER-000",
    "handshake/TV-HS-CONF-000",
    "handshake/TV-HS-INIT-000",
    "handshake/TV-HS-KDF-000",
    "handshake/TV-HS-RESP-000",
    "identity/TV-ID-REV-000",
    "identity/TV-ID-ROT-000",
    "identity/TV-ID-ROT-001",
    "identity/TV-ID-ROT-002",
    "identity/TV-ID-ROT-003",
    "negative/TV-PROTECTED-BAD-000",
    "primitive/TV-PQ-MLDSA-000",
    "primitive/TV-PQ-MLKEM-000",
    "protocol/TV-CLOSE-000",
    "protocol/TV-DATA-000",
    "protocol/TV-ENV-000",
    "ratchet/TV-RATCHET-000",
    "ratchet/TV-RATCHET-001",
    "ratchet/TV-RATCHET-002",
    "ratchet/TV-RATCHET-003",
    "ratchet/TV-RATCHET-004",
    "ratchet/TV-RATCHET-005",
    "ratchet/TV-RATCHET-006",
    "ratchet/TV-RATCHET-007",
    "ratchet/TV-RATCHET-008",
    "ratchet/TV-RATCHET-009",
    "ratchet/TV-RATCHET-010",
    "refresh/TV-REFRESH-000",
    "refresh/TV-REFRESH-001",
    "refresh/TV-REFRESH-002",
];

fn collect_vector_directories(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("read vector directory {}: {error}", directory.display()))?
    {
        let path = entry
            .map_err(|error| format!("read vector entry under {}: {error}", directory.display()))?
            .path();
        if path.is_dir() {
            collect_vector_directories(root, &path, output)?;
        } else if path.file_name().is_some_and(|name| name == "metadata.json") {
            let parent = path
                .parent()
                .and_then(|value| value.strip_prefix(root).ok())
                .ok_or_else(|| {
                    format!("metadata path is outside vector root: {}", path.display())
                })?;
            output.insert(parent.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

pub fn verify(root: &Path) -> Result<(), String> {
    let mut actual = BTreeSet::new();
    collect_vector_directories(root, root, &mut actual)?;
    let expected = EXPECTED_VECTOR_DIRECTORIES
        .iter()
        .copied()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual == expected {
        return Ok(());
    }

    let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
    Err(format!(
        "candidate vector matrix mismatch; missing={missing:?} unexpected={unexpected:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::verify;
    use std::path::Path;

    #[test]
    fn committed_candidate_bundle_matches_required_matrix() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("vector tool lives under repository/qa/tools")
            .join("vectors")
            .join("candidate");
        verify(&root).expect("committed candidate vector matrix");
    }
}
