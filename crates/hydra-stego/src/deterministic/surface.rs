use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
};

use super::lexicon::EventFamily;

const IDENTIFIER_MIN: u64 = 100;
const IDENTIFIER_MAX: u64 = 999;
const PERCENT_MIN: u64 = 18;
const PERCENT_MAX: u64 = 96;
const METRIC_MILLI_MIN: u64 = 5_000;
const METRIC_MILLI_MAX: u64 = 99_999;

/// Non-data-bearing surface variation.
///
/// The deterministic decoder tokenizes only ASCII alphabetic words, so numeric
/// decorations can vary without changing the recovered payload. Identifiers are
/// intentionally intermittent rather than attached to every entity. Metric
/// values and progress values are freshly generated inside bounded ranges.
#[derive(Debug)]
pub(super) struct SurfaceVariation {
    state: u64,
}

impl SurfaceVariation {
    pub(super) fn new() -> Self {
        let random = RandomState::new();
        let mut hasher = random.build_hasher();
        hasher.write_u64(0x4859_4452_4153_5447);
        Self::from_seed(hasher.finish())
    }

    fn from_seed(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    pub(super) fn topic(&mut self, family: EventFamily, topic: &str) -> String {
        let decorate = match family {
            EventFamily::Build => !self.next_u64().is_multiple_of(4),
            EventFamily::Metric => false,
            EventFamily::Deploy => self.next_u64().is_multiple_of(2),
            EventFamily::Trace => self.next_u64().is_multiple_of(3),
        };
        if !decorate {
            return topic.to_owned();
        }
        let identifier = self.range(IDENTIFIER_MIN, IDENTIFIER_MAX);
        if topic.eq_ignore_ascii_case("PR") {
            format!("PR-#{identifier}")
        } else {
            format!("{topic}-{identifier}")
        }
    }

    pub(super) fn status_buffer(&mut self, phrase: &str) -> String {
        if phrase.contains("percent") {
            let percent = self.range(PERCENT_MIN, PERCENT_MAX);
            phrase.replacen("percent", &format!("{percent} percent"), 1)
        } else {
            phrase.to_owned()
        }
    }

    pub(super) fn setting(&mut self, phrase: &str) -> String {
        for marker in [
            "server",
            "system",
            "runner",
            "node",
            "worker",
            "agent",
            "controller",
            "exporter",
            "monitor",
            "shard",
        ] {
            if phrase.contains(marker) && !self.next_u64().is_multiple_of(3) {
                let identifier = self.range(IDENTIFIER_MIN, IDENTIFIER_MAX);
                return phrase.replacen(marker, &format!("{marker}-{identifier}"), 1);
            }
        }
        phrase.to_owned()
    }

    pub(super) fn metric_value(&mut self) -> String {
        let milli = self.range(METRIC_MILLI_MIN, METRIC_MILLI_MAX);
        format!("{}.{:03}", milli / 1_000, milli % 1_000)
    }

    fn range(&mut self, minimum: u64, maximum: u64) -> u64 {
        debug_assert!(minimum <= maximum);
        let width = maximum - minimum + 1;
        minimum + self.next_u64() % width
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_surface_values_stay_inside_their_ranges() {
        let mut surface = SurfaceVariation::from_seed(1);
        for _ in 0..256 {
            let status = surface.status_buffer("Build is percent complete");
            let percent = status
                .split_whitespace()
                .nth(2)
                .unwrap()
                .parse::<u64>()
                .unwrap();
            assert!((PERCENT_MIN..=PERCENT_MAX).contains(&percent));

            let metric = surface.metric_value().parse::<f64>().unwrap();
            assert!((5.0..100.0).contains(&metric));
        }
    }

    #[test]
    fn identifiers_are_intermittent_and_metrics_stay_identifier_free() {
        let mut surface = SurfaceVariation::from_seed(7);
        let build_topics = (0..64)
            .map(|_| surface.topic(EventFamily::Build, "ticket"))
            .collect::<Vec<_>>();
        assert!(build_topics.iter().any(|topic| topic == "ticket"));
        assert!(build_topics
            .iter()
            .any(|topic| topic.starts_with("ticket-")));
        assert_eq!(surface.topic(EventFamily::Metric, "latency"), "latency");
    }

    #[test]
    fn surface_numbers_do_not_add_decoder_words() {
        let mut surface = SurfaceVariation::from_seed(11);
        let decorated = (0..32)
            .map(|_| surface.topic(EventFamily::Build, "PR"))
            .find(|topic| topic != "PR")
            .unwrap();
        assert_eq!(
            super::super::words(&decorated).collect::<Vec<_>>(),
            vec!["PR"]
        );
        assert_eq!(
            super::super::words(&surface.status_buffer("Build is percent complete"))
                .collect::<Vec<_>>(),
            vec!["Build", "is", "percent", "complete"]
        );
        assert!(super::super::words(&surface.metric_value())
            .next()
            .is_none());
    }
}
