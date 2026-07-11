//! Carrier configuration only. HYDRA packets remain opaque to this layer.

/// Carrier selected by the reference app.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CarrierKind {
    /// Exchange packet files manually.
    #[default]
    File,
    /// Move packet bytes through a WebRTC data channel.
    WebRtc,
    /// Move packet bytes through an application relay.
    Relay,
    /// Application-defined carrier name.
    Custom(String),
}

/// Non-secret carrier preferences owned by the app UI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CarrierConfig {
    pub kind: CarrierKind,
    pub endpoint: Option<String>,
}
