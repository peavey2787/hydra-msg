pub(crate) const INDEX_HTML: &str = concat!(
    include_str!("assets/index/shell.html"),
    include_str!("assets/index/chat-settings.html"),
    include_str!("assets/index/security-recovery.html"),
);
pub(crate) const APP_CSS: &str = include_str!("assets/app.css");
pub(crate) const APP_JS: &str = concat!(
    include_str!("assets/app-core.js"),
    include_str!("assets/app-state.js"),
    include_str!("assets/app-render.js"),
    include_str!("assets/app-ui.js"),
    include_str!("assets/app-identity-events.js"),
    include_str!("assets/app-bootstrap-events.js"),
    include_str!("assets/app-chat-events.js"),
    include_str!("assets/app-recovery-events.js"),
    include_str!("assets/app-contact-events.js"),
    include_str!("assets/app-config-events.js"),
);
