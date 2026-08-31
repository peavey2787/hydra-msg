use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    lexicon::{EventFamily, Register, ReportState},
    vocabulary::{BUILD_CONTEXTS, DEPLOY_CONTEXTS, METRIC_CONTEXTS, TRACE_CONTEXTS},
};

const MIN_RECORD_JITTER_US: u64 = 8_000;
const RECORD_JITTER_SPAN_US: u64 = 420_000;

#[derive(Debug, Clone, Copy)]
pub(super) struct CoverContext {
    subject: SubjectContext,
    batch: BatchContext,
    register: Option<Register>,
    base_epoch_micros: u64,
}

impl Default for CoverContext {
    fn default() -> Self {
        let base_epoch_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        Self {
            subject: SubjectContext::default(),
            batch: BatchContext::default(),
            register: None,
            base_epoch_micros,
        }
    }
}

impl CoverContext {
    pub(super) fn timestamp(self) -> String {
        let micros = self
            .base_epoch_micros
            .saturating_add(self.batch.elapsed_micros);
        format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
    }

    pub(super) const fn actor(self, family: EventFamily, choice: u8) -> &'static str {
        let alternate = self.subject.bound && choice != 0;
        match (family, alternate) {
            (EventFamily::Build, false) => "runner",
            (EventFamily::Build, true) => "builder",
            (EventFamily::Metric, false) => "exporter",
            (EventFamily::Metric, true) => "monitor",
            (EventFamily::Deploy, false) => "controller",
            (EventFamily::Deploy, true) => "deployer",
            (EventFamily::Trace, false) => "checker",
            (EventFamily::Trace, true) => "agent",
        }
    }

    pub(super) fn setting(
        self,
        family: EventFamily,
        state: ReportState,
        choice: u8,
    ) -> &'static str {
        let values = match family {
            EventFamily::Build => &BUILD_CONTEXTS,
            EventFamily::Metric => &METRIC_CONTEXTS,
            EventFamily::Deploy => &DEPLOY_CONTEXTS,
            EventFamily::Trace => &TRACE_CONTEXTS,
        };
        if self.batch.is_anchor_record() {
            values[0]
        } else {
            values[(usize::from(choice) + state_offset(state)) & 15]
        }
    }

    pub(super) const fn setting_bits(self) -> usize {
        if self.batch.is_anchor_record() {
            0
        } else {
            4
        }
    }

    pub(super) const fn subject_bits(self) -> usize {
        if self.subject.bound {
            1
        } else {
            0
        }
    }

    pub(super) const fn subject_choices(self) -> u8 {
        1 << self.subject_bits()
    }

    pub(super) const fn register(self, control: u8) -> Register {
        match self.register {
            Some(register) => register,
            None => Register::from_control(control),
        }
    }

    pub(super) fn commit(&mut self, control_choice: u8) {
        self.subject.bind();
        self.batch.advance();
        if self.register.is_none() {
            self.register = Some(Register::from_control(control_choice));
        }
    }
}

const fn state_offset(state: ReportState) -> usize {
    match state {
        ReportState::Planning => 0,
        ReportState::Status => 5,
        ReportState::Transfer => 9,
        ReportState::Closing => 13,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct BatchContext {
    record: u64,
    elapsed_micros: u64,
}

impl BatchContext {
    const fn is_anchor_record(self) -> bool {
        self.record == 0
    }

    fn advance(&mut self) {
        self.elapsed_micros = self
            .elapsed_micros
            .saturating_add(record_jitter_micros(self.record));
        self.record = self.record.wrapping_add(1);
    }
}

const fn record_jitter_micros(record: u64) -> u64 {
    let mut value = record.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    MIN_RECORD_JITTER_US + value % RECORD_JITTER_SPAN_US
}

#[derive(Debug, Clone, Copy, Default)]
struct SubjectContext {
    bound: bool,
}

impl SubjectContext {
    fn bind(&mut self) {
        self.bound = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actors_are_correlated_with_event_family() {
        let mut context = CoverContext::default();
        assert_eq!(context.subject_bits(), 0);
        assert_eq!(context.actor(EventFamily::Build, 0), "runner");
        assert_eq!(context.actor(EventFamily::Metric, 0), "exporter");
        assert_eq!(context.actor(EventFamily::Deploy, 0), "controller");
        assert_eq!(context.actor(EventFamily::Trace, 0), "checker");

        context.commit(0);
        assert_eq!(context.subject_bits(), 1);
        assert_eq!(context.actor(EventFamily::Build, 1), "builder");
        assert_eq!(context.actor(EventFamily::Metric, 1), "monitor");
        assert_eq!(context.actor(EventFamily::Deploy, 1), "deployer");
        assert_eq!(context.actor(EventFamily::Trace, 1), "agent");
    }

    #[test]
    fn context_is_family_specific_and_data_bearing_after_anchor() {
        let mut context = CoverContext::default();
        assert_eq!(context.setting_bits(), 0);
        assert_eq!(
            context.setting(EventFamily::Build, ReportState::Planning, 7),
            BUILD_CONTEXTS[0]
        );
        assert_eq!(
            context.setting(EventFamily::Metric, ReportState::Planning, 7),
            METRIC_CONTEXTS[0]
        );

        context.commit(0);
        assert_eq!(context.setting_bits(), 4);
        for choice in 0_u8..16 {
            assert_eq!(
                context.setting(EventFamily::Deploy, ReportState::Planning, choice),
                DEPLOY_CONTEXTS[usize::from(choice)]
            );
        }
    }

    #[test]
    fn simulated_timestamps_advance_with_microsecond_jitter() {
        let mut context = CoverContext::default();
        let first = context.timestamp();
        context.commit(0);
        let second = context.timestamp();
        context.commit(0);
        let third = context.timestamp();

        let parse = |value: &str| {
            let (seconds, micros) = value.split_once('.').unwrap();
            seconds.parse::<u64>().unwrap() * 1_000_000 + micros.parse::<u64>().unwrap()
        };
        let first = parse(&first);
        let second = parse(&second);
        let third = parse(&third);
        assert!(second > first);
        assert!(third > second);
        assert!(
            (MIN_RECORD_JITTER_US..MIN_RECORD_JITTER_US + RECORD_JITTER_SPAN_US)
                .contains(&(second - first))
        );
        assert!(
            (MIN_RECORD_JITTER_US..MIN_RECORD_JITTER_US + RECORD_JITTER_SPAN_US)
                .contains(&(third - second))
        );
    }
}
