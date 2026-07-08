//! Strict byte-indexed envelope handling for HYDRA-MSG v1.

#![forbid(unsafe_code)]

mod outer_header;
mod protected_record;

pub use outer_header::{
    decode_outer_header, encode_outer_header, validate_envelope_length, OuterHeader, WireError,
};
pub use protected_record::{decode_protected_record, encode_protected_record, ProtectedRecord};
