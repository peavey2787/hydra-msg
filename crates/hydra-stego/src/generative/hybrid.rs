mod codec;
mod template;
mod vocabulary;

#[cfg(test)]
mod tests;

/// Eight five-bit grammatical choices carry five framed bytes per sentence:
/// one choice selects the syntax and seven choose ordinary words.
const BITS_PER_CHOICE: usize = 5;
const CHOICES_PER_SENTENCE: usize = 8;
const BITS_PER_SENTENCE: usize = BITS_PER_CHOICE * CHOICES_PER_SENTENCE;

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| !character.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
}
