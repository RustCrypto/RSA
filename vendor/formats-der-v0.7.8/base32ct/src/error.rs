//! Error types.

use core::fmt;

/// Result type with the `base32ct` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    /// Invalid encoding of provided Base32 string.
    InvalidEncoding,

    /// Insufficient output buffer length.
    InvalidLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidEncoding => f.write_str("invalid Base32 encoding"),
            Error::InvalidLength => f.write_str("invalid Base32 length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
