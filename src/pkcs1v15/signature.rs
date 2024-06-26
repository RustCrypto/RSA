//! `RSASSA-PKCS1-v1_5` signatures.

use crate::algorithms::pad::uint_to_be_pad;
use ::signature::SignatureEncoding;
use alloc::{boxed::Box, string::ToString};
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use num_bigint::BigUint;
#[cfg(feature = "serde")]
use serdect::serde::{de, Deserialize, Serialize};
use spki::{
    der::{asn1::BitString, Result as DerResult},
    SignatureBitStringEncoding,
};

/// `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    pub(super) inner: BigUint,
    pub(super) len: usize,
}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;
}

impl SignatureBitStringEncoding for Signature {
    fn to_bitstring(&self) -> DerResult<BitString> {
        BitString::new(0, self.to_vec())
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Ok(Self {
            inner: BigUint::from_bytes_be(bytes),
            len: bytes.len(),
        })
    }
}

impl From<Signature> for Box<[u8]> {
    fn from(signature: Signature) -> Box<[u8]> {
        uint_to_be_pad(signature.inner, signature.len)
            .expect("RSASSA-PKCS1-v1_5 length invariants should've been enforced")
            .into_boxed_slice()
    }
}

impl Debug for Signature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        fmt.debug_tuple("Signature")
            .field(&self.to_string())
            .finish()
    }
}

impl LowerHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.to_bytes().iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.to_bytes().iter() {
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
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serdect::serde::Deserializer<'de>,
    {
        serdect::slice::deserialize_hex_or_bin_vec(deserializer)?
            .as_slice()
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
        use serde_test::{assert_tokens, Configure, Token};
        let signature = Signature {
            inner: BigUint::new(Vec::from([42])),
            len: 1,
        };

        let tokens = [Token::Str("2a")];
        assert_tokens(&signature.readable(), &tokens);
    }
}
