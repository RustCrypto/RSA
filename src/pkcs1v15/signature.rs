//! `RSASSA-PKCS1-v1_5` signatures.

use ::signature::SignatureEncoding;
use alloc::boxed::Box;
use core::{
    fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex},
    marker::PhantomData,
};
use crypto_bigint::BoxedUint;

use digest::Digest;
#[cfg(feature = "serde")]
use serdect::serde::{de, Deserialize, Serialize};
use signature::PrehashSignature;
use spki::{
    der::{asn1::BitString, Result as DerResult},
    SignatureBitStringEncoding,
};

/// `RSASSA-PKCS1-v1_5` signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Eq)]
pub struct Signature<D> {
    pub(super) inner: BoxedUint,
    _digest: PhantomData<D>,
}

impl<D> Debug for Signature<D> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Signature")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<D> Clone for Signature<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _digest: PhantomData,
        }
    }
}

impl<D> PartialEq for Signature<D> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl<D> SignatureEncoding for Signature<D> {
    type Repr = Box<[u8]>;
}

impl<D> SignatureBitStringEncoding for Signature<D> {
    fn to_bitstring(&self) -> DerResult<BitString> {
        BitString::new(0, self.to_vec())
    }
}

impl<D> TryFrom<&[u8]> for Signature<D> {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        let len = bytes.len();
        let inner = BoxedUint::from_be_slice(bytes, len as u32 * 8);
        #[cfg(feature = "std")]
        let inner = inner
            .map_err(|e| Box::new(e) as Box<dyn core::error::Error + Send + Sync + 'static>)?;
        #[cfg(not(feature = "std"))]
        let inner = inner.map_err(|_| signature::Error::new())?;

        Ok(Self {
            inner,
            _digest: PhantomData,
        })
    }
}

impl<D> From<Signature<D>> for Box<[u8]> {
    fn from(signature: Signature<D>) -> Box<[u8]> {
        signature.inner.to_be_bytes()
    }
}

impl<D> LowerHex for Signature<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.to_bytes().iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<D> UpperHex for Signature<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.to_bytes().iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl<D> Display for Signature<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}

#[cfg(feature = "serde")]
impl<D> Serialize for Signature<D> {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.to_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Di> Deserialize<'de> for Signature<Di> {
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

impl<D> PrehashSignature for Signature<D>
where
    D: Digest,
{
    type Digest = D;
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use serde_test::{assert_tokens, Configure, Token};
        let signature = Signature {
            inner: BoxedUint::from(42u32),
            _digest: PhantomData::<()>,
        };

        let tokens = [Token::Str("000000000000002a")];
        assert_tokens(&signature.readable(), &tokens);
    }
}
