use std::sync::OnceLock;

use super::{
    context::CoverContext,
    lexicon::{EventFamily, LexicalContext, Register, ReportState, RestrictionStyle, Slot},
    surface::SurfaceVariation,
    words, CHOICES_PER_SENTENCE,
};

const TEMPLATE_TEXT: [(&str, EventFamily, RestrictionStyle); 16] = [
    (
        "ts={timestamp} status=\"{control}\" event=build actor=\"{subject}\" action=\"{verb}\" target=\"{qualifier} {topic}\" mode=\"{mode}\" context=\"{setting}\" detail=\"{restriction}\"",
        EventFamily::Build,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} status=\"{control}\" event=test actor=\"{subject}\" action=\"{verb}\" target=\"{qualifier} {topic}\" mode=\"{mode}\" context=\"{setting}\" detail=\"{restriction}\"",
        EventFamily::Build,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} status=\"{control}\" event=package actor=\"{subject}\" action=\"{verb}\" target=\"{qualifier} {topic}\" mode=\"{mode}\" context=\"{setting}\" detail=\"{restriction}\"",
        EventFamily::Build,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} status=\"{control}\" event=artifact actor=\"{subject}\" action=\"{verb}\" target=\"{qualifier} {topic}\" mode=\"{mode}\" context=\"{setting}\" detail=\"{restriction}\"",
        EventFamily::Build,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} metric=\"gauge {qualifier} {topic}\" source=\"{subject} {setting}\" state=\"{control}\" op=\"{mode} {verb}\" value={metric_value}",
        EventFamily::Metric,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} metric=\"counter {qualifier} {topic}\" source=\"{subject} {setting}\" state=\"{control}\" op=\"{mode} {verb}\" value={metric_value}",
        EventFamily::Metric,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} metric=\"histogram {qualifier} {topic}\" source=\"{subject} {setting}\" state=\"{control}\" op=\"{mode} {verb}\" value={metric_value}",
        EventFamily::Metric,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} metric=\"snapshot {qualifier} {topic}\" source=\"{subject} {setting}\" state=\"{control}\" op=\"{mode} {verb}\" value={metric_value}",
        EventFamily::Metric,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} event=deploy target=\"{qualifier} {topic}\" status=\"{control}\" actor=\"{subject}\" context=\"{setting}\" action=\"{verb}\" mode=\"{mode}\"",
        EventFamily::Deploy,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} event=release target=\"{qualifier} {topic}\" status=\"{control}\" actor=\"{subject}\" context=\"{setting}\" action=\"{verb}\" mode=\"{mode}\"",
        EventFamily::Deploy,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} event=rollout target=\"{qualifier} {topic}\" status=\"{control}\" actor=\"{subject}\" context=\"{setting}\" action=\"{verb}\" mode=\"{mode}\"",
        EventFamily::Deploy,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} event=sync target=\"{qualifier} {topic}\" status=\"{control}\" actor=\"{subject}\" context=\"{setting}\" action=\"{verb}\" mode=\"{mode}\"",
        EventFamily::Deploy,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} severity=info event=validation component=\"{setting}\" result=\"{control}\" actor=\"{subject}\" target=\"{qualifier} {topic}\" action=\"{verb}\" mode=\"{mode}\" detail=\"{restriction}\" retry=false",
        EventFamily::Trace,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} severity=warn event=retry component=\"{setting}\" result=\"{control}\" actor=\"{subject}\" target=\"{qualifier} {topic}\" action=\"{verb}\" mode=\"{mode}\" detail=\"{restriction}\" retry=true",
        EventFamily::Trace,
        RestrictionStyle::Scope,
    ),
    (
        "ts={timestamp} severity=warn event=warning component=\"{setting}\" result=\"{control}\" actor=\"{subject}\" target=\"{qualifier} {topic}\" action=\"{verb}\" mode=\"{mode}\" detail=\"{restriction}\" retry=false",
        EventFamily::Trace,
        RestrictionStyle::Evidence,
    ),
    (
        "ts={timestamp} severity=error event=failure component=\"{setting}\" result=\"{control}\" actor=\"{subject}\" target=\"{qualifier} {topic}\" action=\"{verb}\" mode=\"{mode}\" detail=\"{restriction}\" retry=true",
        EventFamily::Trace,
        RestrictionStyle::Scope,
    ),
];

pub(super) fn templates() -> &'static [Template] {
    static TEMPLATES: OnceLock<Vec<Template>> = OnceLock::new();
    TEMPLATES.get_or_init(|| {
        TEMPLATE_TEXT
            .iter()
            .map(|(text, family, restriction_style)| {
                Template::compile(text, *family, *restriction_style)
            })
            .collect()
    })
}

#[derive(Debug)]
pub(super) struct Template {
    family: EventFamily,
    restriction_style: RestrictionStyle,
    present: [bool; CHOICES_PER_SENTENCE - 1],
    render_parts: Vec<RenderPart>,
    word_parts: Vec<WordPart>,
}

impl Template {
    fn compile(text: &str, family: EventFamily, restriction_style: RestrictionStyle) -> Self {
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
                .expect("deterministic template placeholder is closed");
            let marker = &text[open + 1..close];
            render_parts.push(match marker {
                "timestamp" => RenderPart::Timestamp,
                "metric_value" => RenderPart::MetricValue,
                _ => RenderPart::Slot(Slot::from_marker(marker)),
            });
            cursor = close + 1;
        }
        if cursor < text.len() {
            render_parts.push(RenderPart::Literal(text[cursor..].to_owned()));
        }

        let mut word_parts = Vec::new();
        let mut seen = [false; CHOICES_PER_SENTENCE - 1];
        for part in &render_parts {
            match part {
                RenderPart::Literal(literal) => word_parts.extend(
                    words(literal).map(|word| WordPart::Literal(word.to_ascii_lowercase())),
                ),
                RenderPart::Slot(slot) => {
                    assert!(!seen[slot.index()], "template slot appears more than once");
                    seen[slot.index()] = true;
                    word_parts.push(WordPart::Slot(*slot));
                }
                RenderPart::Timestamp | RenderPart::MetricValue => {}
            }
        }
        for required in [
            Slot::Control,
            Slot::Subject,
            Slot::Mode,
            Slot::Verb,
            Slot::Qualifier,
            Slot::Topic,
            Slot::Setting,
        ] {
            assert!(
                seen[required.index()],
                "template omits a required data slot"
            );
        }
        Self {
            family,
            restriction_style,
            present: seen,
            render_parts,
            word_parts,
        }
    }

    pub(super) fn render(
        &self,
        state: ReportState,
        context: &CoverContext,
        values: &[u8],
    ) -> String {
        debug_assert_eq!(values.len(), CHOICES_PER_SENTENCE - 1);
        let register = context.register(values[Slot::Control.index()]);
        let lexical = LexicalContext::new(
            self.family,
            state,
            register,
            self.restriction_style,
            context,
        );
        let mut rendered = String::new();
        let mut surface = SurfaceVariation::new();
        for part in &self.render_parts {
            match part {
                RenderPart::Literal(literal) => rendered.push_str(literal),
                RenderPart::Timestamp => rendered.push_str(&context.timestamp()),
                RenderPart::MetricValue => rendered.push_str(&surface.metric_value()),
                RenderPart::Slot(slot) => {
                    let option = slot.option(lexical, values[slot.index()]);
                    let decorated = match slot {
                        Slot::Control => Some(surface.status_buffer(option)),
                        Slot::Topic => Some(surface.topic(self.family, option)),
                        Slot::Setting => Some(surface.setting(option)),
                        _ => None,
                    };
                    rendered.push_str(decorated.as_deref().unwrap_or(option));
                }
            }
        }
        rendered.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    pub(super) fn parse(
        &self,
        observed: &[&str],
        start: usize,
        state: ReportState,
        context: &CoverContext,
    ) -> Option<(usize, [u8; CHOICES_PER_SENTENCE - 1])> {
        let mut cursor = start;
        let mut values = [0_u8; CHOICES_PER_SENTENCE - 1];
        let mut register = None;
        for part in &self.word_parts {
            match part {
                WordPart::Literal(expected)
                    if observed
                        .get(cursor)
                        .is_some_and(|word| word.eq_ignore_ascii_case(expected)) =>
                {
                    cursor += 1;
                }
                WordPart::Literal(_) => return None,
                WordPart::Slot(slot) => {
                    let active_register = match (slot, register) {
                        (Slot::Control, _) => Register::Standard,
                        (_, Some(register)) => register,
                        (_, None) if slot.is_register_independent() => Register::Standard,
                        (_, None) => return None,
                    };
                    let choice_count = if matches!(slot, Slot::Subject) {
                        context.subject_choices()
                    } else {
                        1_u8 << self.value_bits(context, slot.index())
                    };
                    let (value, end) = match_option(observed, cursor, choice_count, |value| {
                        slot.option(
                            LexicalContext::new(
                                self.family,
                                state,
                                active_register,
                                self.restriction_style,
                                context,
                            ),
                            value,
                        )
                    })?;
                    values[slot.index()] = value;
                    cursor = end;
                    if matches!(slot, Slot::Control) {
                        register = Some(context.register(value));
                    }
                }
            }
        }
        Some((cursor, values))
    }

    pub(super) fn commit(&self, _state: ReportState, context: &mut CoverContext, values: &[u8]) {
        context.commit(values[Slot::Control.index()]);
    }

    pub(super) const fn value_bits(&self, context: &CoverContext, value_index: usize) -> usize {
        if !self.present[value_index] {
            0
        } else if value_index == Slot::Subject.index() {
            context.subject_bits()
        } else if value_index == Slot::Setting.index() {
            context.setting_bits()
        } else {
            4
        }
    }

    #[cfg(test)]
    pub(super) const fn family(&self) -> EventFamily {
        self.family
    }
}

fn match_option(
    observed: &[&str],
    start: usize,
    choice_count: u8,
    option: impl Fn(u8) -> &'static str,
) -> Option<(u8, usize)> {
    (0_u8..choice_count)
        .filter_map(|index| {
            let option = option(index);
            let expected = words(option).collect::<Vec<_>>();
            let end = start.checked_add(expected.len())?;
            let actual = observed.get(start..end)?;
            actual
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
                .then_some((index, end, actual.len()))
        })
        .max_by_key(|(_, _, word_count)| *word_count)
        .map(|(index, end, _)| (index, end))
}

#[derive(Debug)]
enum RenderPart {
    Literal(String),
    Timestamp,
    MetricValue,
    Slot(Slot),
}

#[derive(Debug)]
enum WordPart {
    Literal(String),
    Slot(Slot),
}
