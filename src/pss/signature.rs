//! `RSASSA-PSS` signatures.

use crate::PublicKey;
use alloc::boxed::Box;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use signature::SignatureEncoding;

#[cfg(feature = "serde")]
use serdect::serde::{Deserialize, Serialize, de};
#[cfg(feature = "encoding")]
use spki::{
    SignatureBitStringEncoding,
    der::{
        Result as DerResult,
        asn1::{BitString, BitStringRef},
    },
};

/// `RSASSA-PSS` signatures as described in [RFC8017 § 8.1].
///
/// Decoding with `TryFrom` or serde accepts at most [`Self::MAX_LEN`] bytes.
/// Use [`Self::from_bytes_with_max_len`] to explicitly allow larger signatures.
/// A signature's exact length and value are checked during verification.
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub(super) inner: Box<[u8]>,
}

impl Signature {
    /// Default maximum encoded signature length in bytes.
    ///
    /// Corresponds to the default maximum modulus size, [`PublicKey::MAX_SIZE`].
    pub const MAX_LEN: usize = PublicKey::MAX_SIZE.div_ceil(8);

    /// Decode a signature with an explicit maximum encoded length in bytes.
    ///
    /// The length is checked before allocating. This can be used to accept signatures
    /// for keys larger than [`PublicKey::MAX_SIZE`], or to impose a smaller limit.
    /// The exact length and value are checked against the key during verification.
    ///
    /// Signatures larger than [`Self::MAX_LEN`] must also use this method when
    /// decoding their serialized bytes again. `TryFrom` and serde use the default limit.
    ///
    /// # Errors
    /// Returns an error if `bytes.len()` exceeds `max_len`.
    pub fn from_bytes_with_max_len(bytes: &[u8], max_len: usize) -> signature::Result<Self> {
        if bytes.len() > max_len {
            return Err(signature::Error::new());
        }

        Ok(Self {
            inner: bytes.into(),
        })
    }
}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;
}

#[cfg(feature = "encoding")]
impl SignatureBitStringEncoding for Signature {
    fn to_bitstring(&self) -> DerResult<BitString> {
        BitString::new(0, self.to_vec())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_bytes_with_max_len(bytes, Self::MAX_LEN)
    }
}

#[cfg(feature = "encoding")]
impl TryFrom<BitStringRef<'_>> for Signature {
    type Error = signature::Error;

    fn try_from(bit_string: BitStringRef<'_>) -> signature::Result<Self> {
        Self::try_from(bit_string.as_bytes().ok_or_else(signature::Error::new)?)
    }
}

impl From<Signature> for Box<[u8]> {
    fn from(signature: Signature) -> Box<[u8]> {
        signature.inner
    }
}

impl LowerHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.inner.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.inner.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut buffer = [0u8; Self::MAX_LEN];
        serdect::slice::deserialize_hex_or_bin(&mut buffer, deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use serde_test::{Configure, Token, assert_tokens};
        let signature = Signature {
            inner: Box::new([0, 0, 0, 0, 0, 0, 0, 42]),
        };

        let tokens = [Token::Str("000000000000002a")];
        assert_tokens(&signature.readable(), &tokens);
    }
}
