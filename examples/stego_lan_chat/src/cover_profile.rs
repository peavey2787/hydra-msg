#[derive(Clone, Copy)]
pub(crate) enum CoverProfile {
    Arithmetic,
    FastUnicode,
    FastHybrid,
}

impl CoverProfile {
    pub(crate) const fn phase(self) -> &'static str {
        match self {
            Self::Arithmetic => "Running arithmetic cover generation token by token",
            Self::FastUnicode => "Generating the short visible AI cover",
            Self::FastHybrid => "Generating the short AI introduction and coherent prose layer",
        }
    }

    pub(crate) const fn ready_phase(self) -> &'static str {
        match self {
            Self::Arithmetic => "Arithmetic cover text ready",
            Self::FastUnicode => "Fast Unicode cover text ready",
            Self::FastHybrid => "Fast hybrid prose cover text ready",
        }
    }
}
