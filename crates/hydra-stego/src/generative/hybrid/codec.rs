use crate::{frame, StegoError};

use super::super::{fast, GenerativeCodec, LanguageModel};
use super::{template::templates, words, BITS_PER_CHOICE, BITS_PER_SENTENCE, CHOICES_PER_SENTENCE};

const MAX_INTRO_WORDS: usize = 64;
const MAX_WORDS_PER_SENTENCE: usize = 32;
const MAX_RENDERED_SENTENCE_BYTES: usize = 512;

impl<M: LanguageModel> GenerativeCodec<M> {
    /// Generates a short model-sampled introduction and embeds the framed
    /// payload in varied, printable grammatical prose.
    ///
    /// Model work remains fixed at 16 token selections. The prose codec is
    /// tolerant of case, punctuation, and whitespace normalization, but not
    /// word replacement, deletion, reordering, translation, or paraphrasing.
    /// Hybrid generation with the selected AI-introduction token count
    /// reported after each model inference.
    pub(crate) fn hide_fast_hybrid_with_progress<F>(
        &self,
        payload: &[u8],
        mut on_progress: F,
    ) -> Result<String, StegoError>
    where
        F: FnMut(usize),
    {
        let framed = fast::frame_payload(self, payload)?;
        let generated = fast::generate_visible_cover(self, &framed, &mut on_progress)?;
        let mut cover = printable_ascii(&generated)?;
        if words(&cover).take(MAX_INTRO_WORDS + 1).count() > MAX_INTRO_WORDS {
            return Err(StegoError::Model(
                "fast hybrid introduction exceeds its word limit".to_owned(),
            ));
        }
        ensure_hybrid_capacity(self, cover.len(), framed.len())?;
        cover.push(' ');
        cover.push_str(&encode_prose(&framed)?);
        self.ensure_cover_bytes(&cover)?;
        Ok(cover)
    }

    /// Recovers a payload from the hybrid prose without model inference.
    /// Punctuation, whitespace, and ASCII letter case are intentionally
    /// ignored. The recovered bytes still require HYDRA authentication.
    pub(crate) fn reveal_fast_hybrid(&self, cover_text: &str) -> Result<Vec<u8>, StegoError> {
        self.ensure_cover_bytes(cover_text)?;
        let maximum_words = maximum_cover_words(
            self.config.maximum_payload_bytes,
            self.config.maximum_cover_bytes,
        )?;
        let words = words(cover_text)
            .take(maximum_words + 1)
            .collect::<Vec<_>>();
        if words.len() > maximum_words {
            return Err(StegoError::MalformedCoverText(
                "hybrid carrier exceeds its word limit",
            ));
        }
        let maximum_start = words.len().min(MAX_INTRO_WORDS + 1);
        for start in 0..maximum_start {
            if let Some(payload) =
                decode_prose_at(&words, start, self.config.maximum_payload_bytes)?
            {
                return Ok(payload);
            }
        }
        Err(StegoError::NotCoverText)
    }
}

fn ensure_hybrid_capacity<M: LanguageModel>(
    codec: &GenerativeCodec<M>,
    introduction_bytes: usize,
    framed_bytes: usize,
) -> Result<(), StegoError> {
    let framed_bits = framed_bytes
        .checked_mul(8)
        .ok_or(StegoError::InvalidConfig("hybrid carrier bound overflow"))?;
    let sentences = framed_bits
        .checked_add(BITS_PER_SENTENCE - 1)
        .ok_or(StegoError::InvalidConfig("hybrid carrier bound overflow"))?
        / BITS_PER_SENTENCE;
    let expected_upper_bound = sentences
        .checked_mul(MAX_RENDERED_SENTENCE_BYTES)
        .and_then(|bytes| bytes.checked_add(introduction_bytes))
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(StegoError::InvalidConfig("hybrid carrier bound overflow"))?;
    if expected_upper_bound > codec.config.maximum_cover_bytes {
        return Err(StegoError::CoverTooLarge {
            actual: expected_upper_bound,
            maximum: codec.config.maximum_cover_bytes,
        });
    }
    Ok(())
}

pub(super) fn encode_prose(framed: &[u8]) -> Result<String, StegoError> {
    let mut bits = Vec::with_capacity(framed.len() * 8 + BITS_PER_SENTENCE - 1);
    for byte in framed {
        for shift in (0..8).rev() {
            bits.push(byte >> shift & 1);
        }
    }
    let mut padding_state = framed.iter().fold(0x9e37_79b9_u32, |state, byte| {
        state.rotate_left(5) ^ u32::from(*byte)
    });
    while !bits.len().is_multiple_of(BITS_PER_SENTENCE) {
        padding_state ^= padding_state << 13;
        padding_state ^= padding_state >> 17;
        padding_state ^= padding_state << 5;
        bits.push((padding_state & 1) as u8);
    }

    let mut prose = String::new();
    for record_bits in bits.chunks_exact(BITS_PER_SENTENCE) {
        let choices = record_bits
            .chunks_exact(BITS_PER_CHOICE)
            .map(choice_from_bits)
            .collect::<Vec<_>>();
        let sentence = templates()[usize::from(choices[0])].render(&choices[1..]);
        if sentence.len() > MAX_RENDERED_SENTENCE_BYTES {
            return Err(StegoError::InvalidConfig(
                "hybrid grammar exceeded its sentence byte bound",
            ));
        }
        if !prose.is_empty() {
            prose.push(' ');
        }
        prose.push_str(&sentence);
    }
    Ok(prose)
}

fn decode_prose_at(
    words: &[&str],
    start: usize,
    maximum_payload_bytes: usize,
) -> Result<Option<Vec<u8>>, StegoError> {
    let mut cursor = start;
    let mut framed = Vec::new();
    while cursor < words.len() {
        let mut matched = None;
        for (template_index, template) in templates().iter().enumerate() {
            if let Some((end, values)) = template.parse(words, cursor) {
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
        let mut record_bits = Vec::with_capacity(BITS_PER_SENTENCE);
        for choice in choices {
            push_choice_bits(&mut record_bits, choice);
        }
        framed.extend(
            record_bits
                .chunks_exact(8)
                .map(|bits| bits.iter().fold(0_u8, |byte, bit| byte << 1 | bit)),
        );

        if framed.len() < frame::minimum_encoded_len() {
            continue;
        }
        let expected = match frame::expected_len(&framed, maximum_payload_bytes) {
            Ok(Some(expected)) => expected,
            Ok(None) => continue,
            Err(_) => return Ok(None),
        };
        if framed.len() >= expected {
            return frame::decode(&framed[..expected], maximum_payload_bytes)
                .map(Some)
                .or(Ok(None));
        }
    }
    Ok(None)
}

fn choice_from_bits(bits: &[u8]) -> u8 {
    bits.iter().fold(0_u8, |choice, bit| choice << 1 | bit)
}

fn push_choice_bits(bits: &mut Vec<u8>, choice: u8) {
    for shift in (0..BITS_PER_CHOICE).rev() {
        bits.push(choice >> shift & 1);
    }
}

fn printable_ascii(text: &str) -> Result<String, StegoError> {
    let mut printable = String::with_capacity(text.len());
    let mut pending_space = false;
    for character in text.chars() {
        if character.is_ascii_graphic() {
            if pending_space && !printable.is_empty() {
                printable.push(' ');
            }
            pending_space = false;
            printable.push(character);
        } else {
            pending_space = true;
        }
    }
    if printable.is_empty() {
        return Err(StegoError::Model(
            "fast hybrid profile generated no printable ASCII introduction".to_owned(),
        ));
    }
    if let Some((offset, character)) = printable
        .char_indices()
        .find(|(_, character)| matches!(character, '.' | '!' | '?'))
    {
        printable.truncate(offset + character.len_utf8());
    }
    Ok(printable)
}

fn maximum_cover_words(
    maximum_payload_bytes: usize,
    maximum_cover_bytes: usize,
) -> Result<usize, StegoError> {
    let framed_bytes = maximum_payload_bytes
        .checked_add(frame::ENCODED_OVERHEAD_BYTES)
        .ok_or(StegoError::InvalidConfig("hybrid carrier bound overflow"))?;
    let framed_bits = framed_bytes
        .checked_mul(8)
        .ok_or(StegoError::InvalidConfig("hybrid carrier bound overflow"))?;
    let sentences = framed_bits
        .checked_add(BITS_PER_SENTENCE - 1)
        .ok_or(StegoError::InvalidConfig("hybrid carrier bound overflow"))?
        / BITS_PER_SENTENCE;
    let grammar_bound = sentences
        .checked_mul(MAX_WORDS_PER_SENTENCE)
        .and_then(|words| words.checked_add(MAX_INTRO_WORDS))
        .ok_or(StegoError::InvalidConfig("hybrid word bound overflow"))?;
    let byte_bound = maximum_cover_bytes
        .checked_add(1)
        .ok_or(StegoError::InvalidConfig("hybrid word bound overflow"))?
        / 2;
    Ok(grammar_bound.min(byte_bound))
}
