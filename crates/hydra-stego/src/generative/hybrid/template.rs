use std::sync::OnceLock;

use super::{vocabulary, words, CHOICES_PER_SENTENCE};

pub(super) fn templates() -> &'static [Template] {
    static TEMPLATES: OnceLock<Vec<Template>> = OnceLock::new();
    TEMPLATES.get_or_init(|| {
        vocabulary::TEMPLATE_TEXT
            .iter()
            .map(|text| Template::compile(text))
            .collect()
    })
}

#[derive(Debug)]
pub(super) struct Template {
    render_parts: Vec<RenderPart>,
    word_parts: Vec<WordPart>,
}

impl Template {
    fn compile(text: &str) -> Self {
        let mut render_parts = Vec::new();
        let mut cursor = 0;
        while let Some(relative_open) = text[cursor..].find('{') {
            let open = cursor + relative_open;
            if open > cursor {
                render_parts.push(RenderPart::Literal(text[cursor..open].to_owned()));
            }
            let close = text[open + 1..]
                .find('}')
                .map(|relative| open + 1 + relative)
                .expect("hybrid template placeholder is closed");
            let marker = &text[open + 1..close];
            render_parts.push(RenderPart::Slot(Slot::from_marker(marker)));
            cursor = close + 1;
        }
        if cursor < text.len() {
            render_parts.push(RenderPart::Literal(text[cursor..].to_owned()));
        }

        let mut word_parts = Vec::new();
        for part in &render_parts {
            match part {
                RenderPart::Literal(literal) => word_parts.extend(
                    words(literal).map(|word| WordPart::Literal(word.to_ascii_lowercase())),
                ),
                RenderPart::Slot(slot) => word_parts.push(WordPart::Slot(*slot)),
            }
        }
        assert_eq!(
            word_parts
                .iter()
                .filter(|part| matches!(part, WordPart::Slot(_)))
                .count(),
            CHOICES_PER_SENTENCE - 1,
            "every hybrid template must have seven data-word slots",
        );
        Self {
            render_parts,
            word_parts,
        }
    }

    pub(super) fn render(&self, values: &[u8]) -> String {
        debug_assert_eq!(values.len(), CHOICES_PER_SENTENCE - 1);
        let mut rendered = String::new();
        let mut value_index = 0;
        for part in &self.render_parts {
            match part {
                RenderPart::Literal(literal) => rendered.push_str(literal),
                RenderPart::Slot(slot) => {
                    rendered.push_str(slot.options()[usize::from(values[value_index])]);
                    value_index += 1;
                }
            }
        }
        rendered
    }

    pub(super) fn parse(&self, words: &[&str], start: usize) -> Option<(usize, [u8; 7])> {
        if words.len().saturating_sub(start) < self.word_parts.len() {
            return None;
        }
        let mut cursor = start;
        let mut values = [0_u8; 7];
        let mut value_index = 0;
        for part in &self.word_parts {
            let observed = words[cursor];
            match part {
                WordPart::Literal(expected) if observed.eq_ignore_ascii_case(expected) => {}
                WordPart::Literal(_) => return None,
                WordPart::Slot(slot) => {
                    let value = slot
                        .options()
                        .iter()
                        .position(|option| observed.eq_ignore_ascii_case(option))?;
                    values[value_index] = value as u8;
                    value_index += 1;
                }
            }
            cursor += 1;
        }
        Some((cursor, values))
    }
}

#[derive(Debug)]
enum RenderPart {
    Literal(String),
    Slot(Slot),
}

#[derive(Debug)]
enum WordPart {
    Literal(String),
    Slot(Slot),
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    Opener,
    Manner,
    Action,
    Topic,
    Place,
    Connector,
    Tone,
}

impl Slot {
    fn from_marker(marker: &str) -> Self {
        match marker {
            "opener" => Self::Opener,
            "manner" => Self::Manner,
            "action" => Self::Action,
            "topic" => Self::Topic,
            "place" => Self::Place,
            "connector" => Self::Connector,
            "tone" => Self::Tone,
            _ => panic!("unknown hybrid template marker: {marker}"),
        }
    }

    const fn options(self) -> &'static [&'static str; 32] {
        match self {
            Self::Opener => &vocabulary::OPENERS,
            Self::Manner => &vocabulary::MANNERS,
            Self::Action => &vocabulary::ACTIONS,
            Self::Topic => &vocabulary::TOPICS,
            Self::Place => &vocabulary::PLACES,
            Self::Connector => &vocabulary::CONNECTORS,
            Self::Tone => &vocabulary::TONES,
        }
    }
}
