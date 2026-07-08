//! Local browser GUI for HYDRA-MSG.
//!
//! The GUI is intentionally split into small modules so the local HTTP server,
//! security checks, routing, handlers, assets, and app-state rendering do not
//! become one monolithic control surface.

mod assets;
mod encoding;
mod forms;
mod handlers;
mod html;
mod http;
mod router;
mod security;
mod server;
mod state;

pub use server::run;

#[cfg(test)]
mod tests;
