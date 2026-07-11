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
