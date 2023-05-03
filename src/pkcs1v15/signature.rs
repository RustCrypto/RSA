pub use ::signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    DigestSigner, DigestVerifier, Error, Keypair, RandomizedDigestSigner, RandomizedSigner, Result,
    SignatureEncoding, Signer, Verifier,
};

use alloc::{boxed::Box, string::ToString};
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use num_bigint::BigUint;

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
        signature.inner.to_bytes_be().into_boxed_slice()
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
        write!(f, "{:x}", &self.inner)
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", &self.inner)
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}
