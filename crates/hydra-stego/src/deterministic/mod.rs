//! Model-free machine-status cover text.
//!
//! This profile combines a small CFG, stateful technical word classes, lexical
//! substitutions, four machine-oriented registers, four event-family logfmt
//! schemas, timestamp jitter, and family-correlated fields. It is fast and
//! printable, but its public grammar
//! is fingerprintable and edits to data-bearing words destroy the carrier.

mod codec;
mod context;
mod grammar;
mod lexicon;
mod surface;
mod vocabulary;

#[cfg(test)]
mod tests;

pub(crate) use codec::DeterministicCodec;

const BITS_PER_CHOICE: usize = 4;
const CHOICES_PER_SENTENCE: usize = 9;

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| !character.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
}
