use crate::{frame, StegoError};

use super::{context::CoverContext, lexicon::ReportState};
use super::{grammar::templates, words, BITS_PER_CHOICE, CHOICES_PER_SENTENCE};

const MIN_BITS_PER_RECORD: usize = 24;
const MAX_RENDERED_RECORD_BYTES: usize = 512;
const MAX_WORDS_PER_RECORD: usize = 48;
const MAX_DETERMINISTIC_COVER_BYTES: usize = 128 * 1024 * 1024;

/// A model-free machine-status cover-text codec.
///
/// The first record carries 24-28 framed bits and later records carry 29-33
/// bits through four event-family logfmt schemas with active lexical
/// substitutions. Every record starts with a simulated Unix timestamp carrying
/// microsecond precision and monotonic jitter. Build, metric, deploy, and trace
/// families use different field counts/orders, while actor, context, action,
/// qualifier, and topic vocabularies remain correlated inside each family.
/// Mode and action are separate fields, so split-infinitive and passive modal
/// constructions are not part of the deterministic grammar. Rendered topic,
/// status, and metric decorations may include bounded random numbers; those
/// digits are non-data-bearing and ignored by decoding.
/// Decoding ignores ASCII case, punctuation, whitespace, and randomized
/// numeric surface decorations. Those numbers are cosmetic and do not carry
/// payload bits. It does not tolerate data-bearing word replacement, deletion,
/// insertion, reordering, or paraphrase.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeterministicCodec {
    maximum_payload_bytes: usize,
    maximum_cover_bytes: usize,
    maximum_cover_words: usize,
}

impl DeterministicCodec {
    pub(crate) fn try_new(maximum_payload_bytes: usize) -> Result<Self, StegoError> {
        if !(1..=frame::MAX_PAYLOAD_BYTES).contains(&maximum_payload_bytes) {
            return Err(StegoError::InvalidConfig(
                "maximum payload must be from 1 byte through 64 KiB",
            ));
        }
        let framed_bytes = maximum_payload_bytes
            .checked_add(frame::ENCODED_OVERHEAD_BYTES)
            .ok_or(StegoError::InvalidConfig(
                "deterministic carrier bound overflow",
            ))?;
        let framed_bits = framed_bytes
            .checked_mul(8)
            .ok_or(StegoError::InvalidConfig(
                "deterministic carrier bound overflow",
            ))?;
        let maximum_records =
            framed_bits
                .checked_add(MIN_BITS_PER_RECORD - 1)
                .ok_or(StegoError::InvalidConfig(
                    "deterministic carrier bound overflow",
                ))?
                / MIN_BITS_PER_RECORD;
        let maximum_cover_bytes = maximum_records
            .checked_mul(MAX_RENDERED_RECORD_BYTES)
            .ok_or(StegoError::InvalidConfig(
                "deterministic carrier bound overflow",
            ))?;
        if maximum_cover_bytes > MAX_DETERMINISTIC_COVER_BYTES {
            return Err(StegoError::InvalidConfig(
                "deterministic payload limit would exceed the 128 MiB carrier safety bound",
            ));
        }
        let maximum_cover_words =
            maximum_records
                .checked_mul(MAX_WORDS_PER_RECORD)
                .ok_or(StegoError::InvalidConfig(
                    "deterministic word bound overflow",
                ))?;
        Ok(Self {
            maximum_payload_bytes,
            maximum_cover_bytes,
            maximum_cover_words,
        })
    }

    pub(crate) fn hide(&self, payload: &[u8]) -> Result<String, StegoError> {
        if payload.len() > self.maximum_payload_bytes {
            return Err(StegoError::PayloadTooLarge {
                actual: payload.len(),
                maximum: self.maximum_payload_bytes,
            });
        }

        let framed = frame::encode(payload)?;
        let mut bits = BitSource::new(&framed);
        let mut state = ReportState::Planning;
        let mut context = CoverContext::default();
        let mut cover = String::new();
        while bits.has_data() {
            let mut choices = [0_u8; CHOICES_PER_SENTENCE];
            choices[0] = bits.choice(BITS_PER_CHOICE);
            let template = &templates()[usize::from(choices[0])];
            for (value_index, choice) in choices[1..].iter_mut().enumerate() {
                *choice = bits.choice(template.value_bits(&context, value_index));
            }
            let record = template.render(state, &context, &choices[1..]);
            validate_rendered_record(&record)?;
            let separator_bytes = usize::from(!cover.is_empty());
            let next_len = cover
                .len()
                .checked_add(separator_bytes)
                .and_then(|length| length.checked_add(record.len()))
                .ok_or(StegoError::InvalidConfig(
                    "deterministic carrier length overflow",
                ))?;
            if next_len > self.maximum_cover_bytes {
                return Err(StegoError::CoverTooLarge {
                    actual: next_len,
                    maximum: self.maximum_cover_bytes,
                });
            }
            if separator_bytes != 0 {
                cover.push('\n');
            }
            cover.push_str(&record);
            template.commit(state, &mut context, &choices[1..]);
            state = state.transition(choices[1]);
        }
        Ok(cover)
    }

    pub(crate) fn reveal(&self, cover_text: &str) -> Result<Vec<u8>, StegoError> {
        if cover_text.len() > self.maximum_cover_bytes {
            return Err(StegoError::CoverTooLarge {
                actual: cover_text.len(),
                maximum: self.maximum_cover_bytes,
            });
        }
        let words = words(cover_text)
            .take(self.maximum_cover_words + 1)
            .collect::<Vec<_>>();
        if words.len() > self.maximum_cover_words {
            return Err(StegoError::MalformedCoverText(
                "deterministic carrier exceeds its word limit",
            ));
        }
        self.decode_at(&words, 0)?.ok_or(StegoError::NotCoverText)
    }

    fn decode_at(&self, words: &[&str], start: usize) -> Result<Option<Vec<u8>>, StegoError> {
        let mut state = ReportState::Planning;
        let mut context = CoverContext::default();
        let mut cursor = start;
        let mut decoded_bits = Vec::new();
        let mut framed = Vec::new();

        while cursor < words.len() {
            let mut matched = None;
            for (template_index, template) in templates().iter().enumerate() {
                if let Some((end, values)) = template.parse(words, cursor, state, &context) {
                    if matched.is_some() {
                        return Ok(None);
                    }
                    matched = Some((template_index as u8, end, values));
                }
            }
            let Some((template_index, end, values)) = matched else {
                return Ok(None);
            };
            cursor = end;

            let mut choices = [0_u8; CHOICES_PER_SENTENCE];
            choices[0] = template_index;
            choices[1..].copy_from_slice(&values);
            push_choice_bits(&mut decoded_bits, choices[0], BITS_PER_CHOICE);
            let template = &templates()[usize::from(template_index)];
            for (value_index, choice) in choices[1..].iter().enumerate() {
                push_choice_bits(
                    &mut decoded_bits,
                    *choice,
                    template.value_bits(&context, value_index),
                );
            }
            templates()[usize::from(template_index)].commit(state, &mut context, &values);
            state = state.transition(choices[1]);
            while decoded_bits.len() / 8 > framed.len() {
                let start = framed.len() * 8;
                framed.push(
                    decoded_bits[start..start + 8]
                        .iter()
                        .fold(0_u8, |byte, bit| byte << 1 | bit),
                );
            }

            if framed.len() < frame::minimum_encoded_len() {
                continue;
            }
            let expected = match frame::expected_len(&framed, self.maximum_payload_bytes) {
                Ok(Some(expected)) => expected,
                Ok(None) => continue,
                Err(_) => return Ok(None),
            };
            if framed.len() >= expected {
                return frame::decode(&framed[..expected], self.maximum_payload_bytes)
                    .map(Some)
                    .or(Ok(None));
            }
        }
        Ok(None)
    }
}

fn validate_rendered_record(record: &str) -> Result<(), StegoError> {
    if record.len() > MAX_RENDERED_RECORD_BYTES {
        return Err(StegoError::InvalidConfig(
            "deterministic grammar exceeded its record byte bound",
        ));
    }
    if words(record).take(MAX_WORDS_PER_RECORD + 1).count() > MAX_WORDS_PER_RECORD {
        return Err(StegoError::InvalidConfig(
            "deterministic grammar exceeded its record word bound",
        ));
    }
    Ok(())
}

impl Default for DeterministicCodec {
    fn default() -> Self {
        Self::try_new(64 * 1024).expect("default deterministic limits are valid")
    }
}

struct BitSource<'a> {
    framed: &'a [u8],
    cursor: usize,
    padding_state: u32,
}

impl<'a> BitSource<'a> {
    fn new(framed: &'a [u8]) -> Self {
        Self {
            framed,
            cursor: 0,
            padding_state: framed.iter().fold(0x6d2b_79f5_u32, |state, byte| {
                state.rotate_left(7) ^ u32::from(*byte)
            }),
        }
    }

    const fn has_data(&self) -> bool {
        self.cursor < self.framed.len() * 8
    }

    fn choice(&mut self, width: usize) -> u8 {
        (0..width).fold(0_u8, |choice, _| choice << 1 | self.bit())
    }

    fn bit(&mut self) -> u8 {
        let bit = if self.has_data() {
            self.framed[self.cursor / 8] >> (7 - self.cursor % 8) & 1
        } else {
            self.padding_state ^= self.padding_state << 13;
            self.padding_state ^= self.padding_state >> 17;
            self.padding_state ^= self.padding_state << 5;
            (self.padding_state & 1) as u8
        };
        self.cursor += 1;
        bit
    }
}

fn push_choice_bits(bits: &mut Vec<u8>, choice: u8, width: usize) {
    debug_assert!(choice < (1 << width));
    for shift in (0..width).rev() {
        bits.push(choice >> shift & 1);
    }
}
