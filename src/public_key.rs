//! RSA public key type.

use crate::traits::{PaddingScheme, PublicKeyParts, SignatureScheme};
use crate::{Error, Result, RsaPrivateKey};
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use core::ops::RangeInclusive;
use crypto_bigint::modular::BoxedMontyParams;
use crypto_bigint::{BoxedUint, Integer, NonZero, Odd};
use rand_core::CryptoRng;

#[cfg(feature = "serde")]
use {
    serdect::serde::{Deserialize, Serialize, de, ser},
    spki::{DecodePublicKey, EncodePublicKey},
};

/// Represents the public part of an RSA key.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// Modulus: product of prime numbers `p` and `q`
    pub(crate) n: NonZero<BoxedUint>,

    /// Public exponent: power to which a plaintext message is raised in
    /// order to encrypt it.
    ///
    /// The recommended value is `0x10001` (`65537`).
    pub(crate) e: BoxedUint,

    /// `n` represented as its Montgomery parameters.
    pub(crate) n_params: BoxedMontyParams,
}

impl RsaPublicKey {
    /// Default minimum size of the modulus `n` in bits.
    pub const MIN_SIZE: usize = 1024;

    /// Default maximum size of the modulus `n` in bits.
    pub const MAX_SIZE: usize = 8192;

    /// Minimum value of the public exponent `e`.
    pub const MIN_PUB_EXPONENT: u64 = 2;

    /// Maximum value of the public exponent `e`.
    ///
    /// Very large public exponents are a potential denial-of-service vector (a.k.a. "RSADoS")
    /// because they increase the amount of work required for e.g. signature verification. See:
    ///
    /// <https://www.imperialviolet.org/2012/03/17/rsados.html>
    ///
    /// The particular constant below has been chosen to align with *ring* where this value was
    /// selected based on the history of this particular issue, API compatibility concerns, and
    /// benchmark-driven evaluation. See RustCrypto/RSA#155.
    ///
    /// If for some reason you have a legitimate reason to use keys with public exponents larger
    /// than this value, use the special APIs:
    ///
    /// - [`RsaPublicKey::new_unchecked`]
    /// - [`RsaPrivateKey::from_components_with_large_exponent`]
    pub const MAX_PUB_EXPONENT: u64 = (1 << 33) - 1;

    /// Encrypt the given message.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    pub fn encrypt<R: CryptoRng + ?Sized, P: PaddingScheme>(
        &self,
        rng: &mut R,
        padding: P,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        padding.encrypt(rng, self, msg)
    }

    /// Verify a signed message.
    ///
    /// `hashed` must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    ///
    /// If the message is valid `Ok(())` is returned, otherwise an `Err` indicating failure.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    pub fn verify<S: SignatureScheme>(&self, scheme: S, hashed: &[u8], sig: &[u8]) -> Result<()> {
        scheme.verify(self, hashed, sig)
    }

    /// Create a new public key from its components.
    ///
    /// Accepts modulus sizes from [`Self::MIN_SIZE`] to [`Self::MAX_SIZE`], inclusive.
    /// Use [`Self::new_with_size_limits`] to explicitly allow other sizes.
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    pub fn new(n: BoxedUint, e: BoxedUint) -> Result<Self> {
        Self::new_with_size_limits(n, e, Self::MIN_SIZE..=Self::MAX_SIZE)
    }

    /// Create a new public key with explicit, inclusive modulus size limits in bits.
    ///
    /// All other public-key checks still apply. Allowing a smaller minimum can admit insecure
    /// keys and is intended for testing or compatibility with legacy systems.
    ///
    /// For encoded keys outside the default limits, decode the components with the `pkcs1`
    /// crate and pass them to this constructor explicitly.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArguments`] for an empty range, [`Error::ModulusTooSmall`] or
    /// [`Error::ModulusTooLarge`] for a modulus outside the range, or an error if the modulus
    /// or public exponent is invalid.
    pub fn new_with_size_limits(
        n: BoxedUint,
        e: BoxedUint,
        size_range_bits: RangeInclusive<usize>,
    ) -> Result<Self> {
        if size_range_bits.is_empty() {
            return Err(Error::InvalidArguments);
        }

        if (n.bits_vartime() as usize) < *size_range_bits.start() {
            return Err(Error::ModulusTooSmall);
        }

        check_public_with_max_size(&n, &e, Some(*size_range_bits.end()))?;

        let n_odd = Odd::new(n.clone())
            .into_option()
            .ok_or(Error::InvalidModulus)?;
        let n_params = BoxedMontyParams::new(n_odd);
        let n = NonZero::new(n).expect("checked above");

        Ok(Self { n, e, n_params })
    }

    /// Create a new public key with the default minimum modulus size and a custom maximum.
    #[deprecated(since = "0.10.0", note = "please use `new_with_size_limits` instead")]
    #[allow(clippy::missing_errors_doc, reason = "TODO")]
    pub fn new_with_max_size(n: BoxedUint, e: BoxedUint, max_size: usize) -> Result<Self> {
        Self::new_with_size_limits(n, e, Self::MIN_SIZE..=max_size)
    }

    /// Create a new public key, bypassing checks around the modulus and public
    /// exponent size.
    ///
    /// This method is not recommended, and only intended for unusual use cases.
    /// Most applications should use [`RsaPublicKey::new`] or
    /// [`RsaPublicKey::new_with_size_limits`] instead.
    #[must_use]
    pub fn new_unchecked(n: BoxedUint, e: BoxedUint) -> Self {
        let n_odd = Odd::new(n.clone()).expect("n must be odd");
        let n_params = BoxedMontyParams::new(n_odd);
        let n = NonZero::new(n).expect("odd numbers are non zero");

        Self { n, e, n_params }
    }
}

impl Eq for RsaPublicKey {}
impl PartialEq for RsaPublicKey {
    #[inline]
    fn eq(&self, other: &RsaPublicKey) -> bool {
        self.n == other.n && self.e == other.e
    }
}

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: RsaPrivateKey) -> Self {
        (&private_key).into()
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: &RsaPrivateKey) -> Self {
        let n = PublicKeyParts::n(private_key);
        let e = PublicKeyParts::e(private_key);
        let n_params = PublicKeyParts::n_params(private_key);
        RsaPublicKey {
            n: n.clone(),
            e: e.clone(),
            n_params: n_params.clone(),
        }
    }
}

impl Hash for RsaPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Domain separator for RSA private keys
        state.write(b"RsaPublicKey");
        // TODO(tarcieri): to match the `PartialEq` impl we should strip leading zeros
        Hash::hash(&self.n.as_limbs(), state);
        Hash::hash(&self.e.as_limbs(), state);
    }
}

impl PublicKeyParts for RsaPublicKey {
    fn n(&self) -> &NonZero<BoxedUint> {
        &self.n
    }

    fn e(&self) -> &BoxedUint {
        &self.e
    }

    fn n_params(&self) -> &BoxedMontyParams {
        &self.n_params
    }
}

#[cfg(feature = "serde")]
impl Serialize for RsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> core::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self.to_public_key_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for RsaPublicKey {
    fn deserialize<D>(deserializer: D) -> core::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let der_bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::from_public_key_der(&der_bytes).map_err(de::Error::custom)
    }
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
pub(crate) fn check_public(public_key: &impl PublicKeyParts) -> Result<()> {
    check_public_with_max_size(public_key.n(), public_key.e(), None)
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
fn check_public_with_max_size(n: &BoxedUint, e: &BoxedUint, max_size: Option<usize>) -> Result<()> {
    if let Some(max_size) = max_size {
        if n.bits_vartime() as usize > max_size {
            return Err(Error::ModulusTooLarge);
        }
    }

    check_public_skip_exponent_size(n, e)?;

    if e < &BoxedUint::from(RsaPublicKey::MIN_PUB_EXPONENT) {
        return Err(Error::PublicExponentTooSmall);
    }

    if e > &BoxedUint::from(RsaPublicKey::MAX_PUB_EXPONENT) {
        return Err(Error::PublicExponentTooLarge);
    }

    Ok(())
}

/// Check that the public key is well formed, skipping exponent size bounds checks.
///
/// This is used internally by both public validation functions and hazmat APIs.
#[inline]
pub(crate) fn check_public_skip_exponent_size(n: &BoxedUint, e: &BoxedUint) -> Result<()> {
    if e >= n || n.is_even().into() || n.is_zero().into() {
        return Err(Error::InvalidModulus);
    }

    if e.is_even().into() {
        return Err(Error::InvalidExponent);
    }

    // Skip exponent size bounds checks
    Ok(())
}
