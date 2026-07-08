use core::fmt;

pub type CryptoResult<T> = Result<T, CryptoError>;

/// Local failures. Variants never contain secret or peer-controlled buffers
/// and must be collapsed at a remote trust boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidEncoding(&'static str),
    AuthenticationFailed,
    WeakPublicKey,
    EntropyUnavailable,
    OutputTooLong,
    BackendFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid {field} length: expected {expected}, got {actual}"
            ),
            Self::InvalidEncoding(field) => write!(f, "invalid {field} encoding"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::WeakPublicKey => f.write_str("rejected weak public key"),
            Self::EntropyUnavailable => f.write_str("operating-system entropy unavailable"),
            Self::OutputTooLong => f.write_str("requested KDF output is too long"),
            Self::BackendFailure => f.write_str("cryptographic backend failure"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub(crate) fn exact_array<const N: usize>(
    field: &'static str,
    input: &[u8],
) -> CryptoResult<[u8; N]> {
    input.try_into().map_err(|_| CryptoError::InvalidLength {
        field,
        expected: N,
        actual: input.len(),
    })
}
