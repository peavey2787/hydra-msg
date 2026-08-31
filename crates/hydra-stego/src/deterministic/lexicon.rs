use super::{context::CoverContext, vocabulary::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReportState {
    Planning,
    Status,
    Transfer,
    Closing,
}

impl ReportState {
    /// The low control bits retain a small state machine so successive records
    /// rotate within the same event-family vocabulary instead of sampling a
    /// completely flat product distribution.
    pub(super) const fn transition(self, control: u8) -> Self {
        match control & 0b11 {
            0 => self,
            1 => match self {
                Self::Planning => Self::Status,
                Self::Status => Self::Transfer,
                Self::Transfer | Self::Closing => Self::Closing,
            },
            2 => Self::Planning,
            _ => Self::Closing,
        }
    }

    const fn offset(self) -> usize {
        match self {
            Self::Planning => 0,
            Self::Status => 5,
            Self::Transfer => 9,
            Self::Closing => 13,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EventFamily {
    Build,
    Metric,
    Deploy,
    Trace,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Register {
    Formal,
    Standard,
    Compact,
    Terse,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RestrictionStyle {
    Evidence,
    Scope,
}

#[derive(Clone, Copy)]
pub(super) struct LexicalContext<'a> {
    family: EventFamily,
    state: ReportState,
    register: Register,
    restriction_style: RestrictionStyle,
    cover: &'a CoverContext,
}

impl<'a> LexicalContext<'a> {
    pub(super) const fn new(
        family: EventFamily,
        state: ReportState,
        register: Register,
        restriction_style: RestrictionStyle,
        cover: &'a CoverContext,
    ) -> Self {
        Self {
            family,
            state,
            register,
            restriction_style,
            cover,
        }
    }
}

impl Register {
    pub(super) const fn from_control(control: u8) -> Self {
        match control >> 2 {
            0 => Self::Formal,
            1 => Self::Standard,
            2 => Self::Compact,
            _ => Self::Terse,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Slot {
    Control,
    Subject,
    Mode,
    Verb,
    Qualifier,
    Topic,
    Setting,
    Restriction,
}

impl Slot {
    pub(super) fn from_marker(marker: &str) -> Self {
        match marker {
            "control" => Self::Control,
            "subject" => Self::Subject,
            "mode" => Self::Mode,
            "verb" => Self::Verb,
            "qualifier" => Self::Qualifier,
            "topic" => Self::Topic,
            "setting" => Self::Setting,
            "restriction" => Self::Restriction,
            _ => panic!("unknown deterministic template marker: {marker}"),
        }
    }

    pub(super) const fn index(self) -> usize {
        match self {
            Self::Control => 0,
            Self::Subject => 1,
            Self::Mode => 2,
            Self::Verb => 3,
            Self::Qualifier => 4,
            Self::Topic => 5,
            Self::Setting => 6,
            Self::Restriction => 7,
        }
    }

    pub(super) const fn is_register_independent(self) -> bool {
        matches!(
            self,
            Self::Subject
                | Self::Verb
                | Self::Qualifier
                | Self::Topic
                | Self::Setting
                | Self::Restriction
        )
    }

    pub(super) fn option(self, lexical: LexicalContext<'_>, value: u8) -> &'static str {
        let LexicalContext {
            family,
            state,
            register,
            restriction_style,
            cover,
        } = lexical;
        let index = rotated_index(state, usize::from(value));
        match self {
            Self::Control => control_values(family)[usize::from(value)],
            Self::Subject => cover.actor(family, value),
            Self::Mode => action_modes(register)[usize::from(value)],
            Self::Verb => actions(family)[index],
            Self::Qualifier => qualifiers(family)[index],
            Self::Topic => topics(family)[index],
            Self::Setting => cover.setting(family, state, value),
            Self::Restriction if matches!(restriction_style, RestrictionStyle::Evidence) => {
                EVIDENCE_RESTRICTIONS[index]
            }
            Self::Restriction => SCOPE_RESTRICTIONS[index],
        }
    }
}

const fn rotated_index(state: ReportState, index: usize) -> usize {
    (index + state.offset()) & 15
}

const fn control_values(family: EventFamily) -> &'static [&'static str; 16] {
    match family {
        EventFamily::Build => &BUILD_STATES,
        EventFamily::Metric => &METRIC_STATES,
        EventFamily::Deploy => &DEPLOY_STATES,
        EventFamily::Trace => &TRACE_RESULTS,
    }
}

const fn action_modes(register: Register) -> &'static [&'static str; 16] {
    match register {
        Register::Formal => &FORMAL_ACTION_MODES,
        Register::Standard => &STANDARD_ACTION_MODES,
        Register::Compact => &COMPACT_ACTION_MODES,
        Register::Terse => &TERSE_ACTION_MODES,
    }
}

const fn actions(family: EventFamily) -> &'static [&'static str; 16] {
    match family {
        EventFamily::Build => &BUILD_ACTIONS,
        EventFamily::Metric => &METRIC_ACTIONS,
        EventFamily::Deploy => &DEPLOY_ACTIONS,
        EventFamily::Trace => &TRACE_ACTIONS,
    }
}

const fn qualifiers(family: EventFamily) -> &'static [&'static str; 16] {
    match family {
        EventFamily::Build => &BUILD_QUALIFIERS,
        EventFamily::Metric => &METRIC_QUALIFIERS,
        EventFamily::Deploy => &DEPLOY_QUALIFIERS,
        EventFamily::Trace => &TRACE_QUALIFIERS,
    }
}

const fn topics(family: EventFamily) -> &'static [&'static str; 16] {
    match family {
        EventFamily::Build => &BUILD_TOPICS,
        EventFamily::Metric => &METRIC_TOPICS,
        EventFamily::Deploy => &DEPLOY_TOPICS,
        EventFamily::Trace => &TRACE_TOPICS,
    }
}
