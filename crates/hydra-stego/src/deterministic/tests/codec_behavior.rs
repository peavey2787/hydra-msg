use super::super::DeterministicCodec;
use crate::StegoError;

#[test]
fn deterministic_profile_round_trips_printable_machine_status_text() {
    let codec = DeterministicCodec::try_new(4096).unwrap();
    let secret = b"opaque encrypted HYDRA packet";
    let cover = codec.hide(secret).unwrap();

    assert_eq!(codec.reveal(&cover).unwrap(), secret);
    assert!(cover.is_ascii());
    assert!(!cover.contains("opaque encrypted HYDRA packet"));
    assert!(cover.lines().all(|line| line.starts_with("ts=")));
    assert!(cover.contains(" action=\""));
}

#[test]
fn deterministic_stream_has_monotonic_microsecond_timestamps() {
    let codec = DeterministicCodec::default();
    let cover = codec
        .hide(b"timestamp jitter across several records")
        .unwrap();
    let timestamps = cover
        .lines()
        .map(|line| {
            let raw = line
                .split_whitespace()
                .next()
                .unwrap()
                .strip_prefix("ts=")
                .unwrap();
            let (seconds, micros) = raw.split_once('.').unwrap();
            assert_eq!(micros.len(), 6);
            seconds.parse::<u64>().unwrap() * 1_000_000 + micros.parse::<u64>().unwrap()
        })
        .collect::<Vec<_>>();
    assert!(timestamps.len() > 1);
    assert!(timestamps.windows(2).all(|pair| pair[1] > pair[0]));
}

#[test]
fn deterministic_profile_survives_surface_normalization() {
    let codec = DeterministicCodec::default();
    let cover = codec.hide(b"surface normalization").unwrap();
    let normalized = cover
        .chars()
        .map(|character| {
            if character.is_ascii_punctuation() {
                ' '
            } else {
                character.to_ascii_uppercase()
            }
        })
        .collect::<String>();

    assert_eq!(codec.reveal(&normalized).unwrap(), b"surface normalization");
}

#[test]
fn randomized_numeric_surface_is_not_data_bearing() {
    let codec = DeterministicCodec::default();
    let secret = b"numeric decorations are cosmetic";
    let cover = codec.hide(secret).unwrap();
    let rewritten = cover
        .chars()
        .map(|character| {
            if character.is_ascii_digit() {
                '7'
            } else {
                character
            }
        })
        .collect::<String>();
    assert_eq!(codec.reveal(&rewritten).unwrap(), secret);
}

#[test]
fn deterministic_profile_rejects_unframed_prefix_words() {
    let codec = DeterministicCodec::default();
    let cover = codec.hide(b"strict carrier boundary").unwrap();
    let prefixed = format!("unrelated prefix {cover}");
    assert_eq!(
        codec.reveal(&prefixed).unwrap_err(),
        StegoError::NotCoverText
    );
}

#[test]
fn deterministic_profile_rejects_word_edits() {
    let codec = DeterministicCodec::default();
    let cover = codec.hide(b"authenticated elsewhere").unwrap();
    let edited = cover.replacen("action", "MUTATED", 1);
    assert_eq!(codec.reveal(&edited).unwrap_err(), StegoError::NotCoverText);
}
#[test]
fn deterministic_configuration_accepts_maximum_and_rejects_out_of_range_bounds() {
    assert!(DeterministicCodec::try_new(crate::frame::MAX_PAYLOAD_BYTES).is_ok());
    assert!(matches!(
        DeterministicCodec::try_new(0),
        Err(StegoError::InvalidConfig(_))
    ));
    assert!(matches!(
        DeterministicCodec::try_new(crate::frame::MAX_PAYLOAD_BYTES + 1),
        Err(StegoError::InvalidConfig(_))
    ));
}

#[test]
fn deterministic_profile_enforces_payload_limit() {
    let codec = DeterministicCodec::try_new(3).unwrap();
    assert_eq!(
        codec.hide(b"four").unwrap_err(),
        StegoError::PayloadTooLarge {
            actual: 4,
            maximum: 3
        },
    );
}
