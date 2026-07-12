use super::{
    outbound::split_payload_for_packets, records::decode_fragment_record, FragmentKind,
    FragmentScope,
};

#[test]
fn fragment_records_round_trip() {
    let payload = vec![7_u8; 10_000];
    let records = split_payload_for_packets(FragmentScope::Direct, &payload, 4_096).unwrap();
    assert!(records.len() > 1);
    let mut out = Vec::new();
    for record in records {
        let part = decode_fragment_record(&record).unwrap().unwrap();
        assert_eq!(part.kind, FragmentKind::Direct);
        out.extend(part.bytes);
    }
    assert_eq!(out, payload);
}

#[test]
fn fragment_count_and_index_boundaries_are_exact() {
    use super::records::encode_fragment_record;
    use crate::limits::MAX_FRAGMENTS_PER_MESSAGE;

    let max_total = encode_fragment_record(
        FragmentScope::Direct,
        [1; 32],
        MAX_FRAGMENTS_PER_MESSAGE as u32,
        0,
        b"",
    );
    assert!(decode_fragment_record(&max_total).unwrap().is_some());

    let too_many = encode_fragment_record(
        FragmentScope::Direct,
        [1; 32],
        (MAX_FRAGMENTS_PER_MESSAGE + 1) as u32,
        0,
        b"",
    );
    assert!(decode_fragment_record(&too_many).is_err());

    let index_equal_to_total = encode_fragment_record(FragmentScope::Direct, [1; 32], 1, 1, b"");
    assert!(decode_fragment_record(&index_equal_to_total).is_err());

    let zero_total = encode_fragment_record(FragmentScope::Direct, [1; 32], 0, 0, b"");
    assert!(decode_fragment_record(&zero_total).is_err());
}

#[test]
fn candidate_direct_fragment_vectors_decode_and_reassemble() {
    const EXPECTED: &[u8] =
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-DIRECT-000/payload.bin");
    let records: [&[u8]; 3] = [
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-DIRECT-000/part_0.bin"),
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-DIRECT-000/part_1.bin"),
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-DIRECT-000/part_2.bin"),
    ];

    let mut reassembled = Vec::new();
    for (expected_index, record) in records.into_iter().enumerate() {
        let part = decode_fragment_record(record).unwrap().unwrap();
        assert_eq!(part.kind, FragmentKind::Direct);
        assert_eq!(part.lobby_id, None);
        assert_eq!(part.total, 3);
        assert_eq!(part.index, expected_index);
        reassembled.extend_from_slice(&part.bytes);
    }
    assert_eq!(reassembled, EXPECTED);
}

#[test]
fn candidate_lobby_fragment_vectors_preserve_scope() {
    use crate::LobbyId;

    const LOBBY_ID: &[u8] =
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-LOBBY-000/lobby_id.bin");
    const EXPECTED: &[u8] =
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-LOBBY-000/payload.bin");
    let lobby_id = LobbyId(LOBBY_ID.try_into().unwrap());
    let records: [&[u8]; 2] = [
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-LOBBY-000/part_0.bin"),
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-LOBBY-000/part_1.bin"),
    ];

    let mut reassembled = Vec::new();
    for (expected_index, record) in records.into_iter().enumerate() {
        let part = decode_fragment_record(record).unwrap().unwrap();
        assert_eq!(part.kind, FragmentKind::Lobby);
        assert_eq!(part.lobby_id, Some(lobby_id));
        assert_eq!(part.total, 2);
        assert_eq!(part.index, expected_index);
        reassembled.extend_from_slice(&part.bytes);
    }
    assert_eq!(reassembled, EXPECTED);
}

#[test]
fn candidate_negative_fragment_vectors_fail_closed() {
    let malformed: [&[u8]; 6] = [
        include_bytes!("../../../../qa/vectors/candidate/fragment/TV-FRAG-BAD-000/zero_total.bin"),
        include_bytes!(
            "../../../../qa/vectors/candidate/fragment/TV-FRAG-BAD-000/index_equal_total.bin"
        ),
        include_bytes!(
            "../../../../qa/vectors/candidate/fragment/TV-FRAG-BAD-000/total_over_limit.bin"
        ),
        include_bytes!(
            "../../../../qa/vectors/candidate/fragment/TV-FRAG-BAD-000/unknown_kind.bin"
        ),
        include_bytes!(
            "../../../../qa/vectors/candidate/fragment/TV-FRAG-BAD-000/trailing_bytes.bin"
        ),
        include_bytes!(
            "../../../../qa/vectors/candidate/fragment/TV-FRAG-BAD-000/declared_length_overrun.bin"
        ),
    ];

    for record in malformed {
        assert!(decode_fragment_record(record).is_err());
    }
}
