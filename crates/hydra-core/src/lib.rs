//! Core protocol constants, closed discriminants, and shared HYDRA-MSG types.
//!
//! This crate intentionally performs no raw cryptographic operations and no
//! wire encoding.

#![forbid(unsafe_code)]

pub mod constants;
pub mod error;
pub mod protocol;
pub mod test_support;
pub mod types;

pub use constants::*;
pub use error::{HydraError, HydraResult};
