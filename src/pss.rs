//! Support for the [Probabilistic Signature Scheme] (PSS) a.k.a. RSASSA-PSS.
//!
//! Designed by Mihir Bellare and Phillip Rogaway. Specified in [RFC8017 § 8.1].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pss-signatures).
//!
//! [Probabilistic Signature Scheme]: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
//! [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1

use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::fmt::{self, Debug, Display, Formatter, LowerHex, UpperHex};
use core::marker::PhantomData;

use const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{Digest, DynDigest, FixedOutputReset};
use num_bigint::BigUint;
use pkcs1::RsaPssParams;
use pkcs8::{
    spki::{
        der::{Any, AnyRef},
        AlgorithmIdentifierOwned, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier,
        DynSignatureAlgorithmIdentifier,
    },
    Document, EncodePrivateKey, EncodePublicKey, SecretDocument,
};
use rand_core::CryptoRngCore;
use signature::{
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner, SignatureEncoding, Verifier,
};

use crate::algorithms::pss::*;
use crate::errors::{Error, Result};
use crate::internals::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::key::PublicKeyParts;
use crate::padding::SignatureScheme;
use crate::{RsaPrivateKey, RsaPublicKey};

#[cfg(feature = "getrandom")]
use {rand_core::OsRng, signature::Signer};

/// Digital signatures using PSS padding.
pub struct Pss {
    /// Create blinded signatures.
    pub blinded: bool,

    /// Digest type to use.
    pub digest: Box<dyn DynDigest + Send + Sync>,

    /// Salt length.
    pub salt_len: usize,
}

impl Pss {
    /// New PSS padding for the given digest.
    /// Digest output size is used as a salt length.
    pub fn new<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self::new_with_salt::<T>(<T as Digest>::output_size())
    }

    /// New PSS padding for the given digest with a salt value of the given length.
    pub fn new_with_salt<T: 'static + Digest + DynDigest + Send + Sync>(len: usize) -> Self {
        Self {
            blinded: false,
            digest: Box::new(T::new()),
            salt_len: len,
        }
    }

    /// New PSS padding for blinded signatures (RSA-BSSA) for the given digest.
    /// Digest output size is used as a salt length.
    pub fn new_blinded<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self::new_blinded_with_salt::<T>(<T as Digest>::output_size())
    }

    /// New PSS padding for blinded signatures (RSA-BSSA) for the given digest
    /// with a salt value of the given length.
    pub fn new_blinded_with_salt<T: 'static + Digest + DynDigest + Send + Sync>(
        len: usize,
    ) -> Self {
        Self {
            blinded: true,
            digest: Box::new(T::new()),
            salt_len: len,
        }
    }
}

impl SignatureScheme for Pss {
    fn sign<Rng: CryptoRngCore>(
        mut self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>> {
        sign(
            rng.ok_or(Error::InvalidPaddingScheme)?,
            self.blinded,
            priv_key,
            hashed,
            self.salt_len,
            &mut *self.digest,
        )
    }

    fn verify(mut self, pub_key: &RsaPublicKey, hashed: &[u8], sig: &[u8]) -> Result<()> {
        verify(
            pub_key,
            hashed,
            &BigUint::from_bytes_be(sig),
            sig.len(),
            &mut *self.digest,
            self.salt_len,
        )
    }
}

impl Debug for Pss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PSS")
            .field("blinded", &self.blinded)
            .field("digest", &"...")
            .field("salt_len", &self.salt_len)
            .finish()
    }
}

/// RSASSA-PSS signatures as described in [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    inner: BigUint,
    len: usize,
}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Ok(Self {
            len: bytes.len(),
            inner: BigUint::from_bytes_be(bytes),
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

pub(crate) fn verify(
    pub_key: &RsaPublicKey,
    hashed: &[u8],
    sig: &BigUint,
    sig_len: usize,
    digest: &mut dyn DynDigest,
    salt_len: usize,
) -> Result<()> {
    if sig_len != pub_key.size() {
        return Err(Error::Verification);
    }

    let mut em = uint_to_be_pad(pub_key.raw_int_encryption_primitive(sig)?, pub_key.size())?;

    emsa_pss_verify(hashed, &mut em, salt_len, digest, pub_key.n().bits())
}

pub(crate) fn verify_digest<D>(
    pub_key: &RsaPublicKey,
    hashed: &[u8],
    sig: &BigUint,
    sig_len: usize,
    salt_len: usize,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    if sig_len != pub_key.size() {
        return Err(Error::Verification);
    }

    let mut em = uint_to_be_pad(pub_key.raw_int_encryption_primitive(sig)?, pub_key.size())?;

    emsa_pss_verify_digest::<D>(hashed, &mut em, salt_len, pub_key.n().bits())
}

/// SignPSS calculates the signature of hashed using RSASSA-PSS.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. The opts argument may be nil, in which case sensible
/// defaults are used.
pub(crate) fn sign<T: CryptoRngCore>(
    rng: &mut T,
    blind: bool,
    priv_key: &RsaPrivateKey,
    hashed: &[u8],
    salt_len: usize,
    digest: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let mut salt = vec![0; salt_len];
    rng.fill_bytes(&mut salt[..]);

    sign_pss_with_salt(blind.then_some(rng), priv_key, hashed, &salt, digest)
}

pub(crate) fn sign_digest<T: CryptoRngCore + ?Sized, D: Digest + FixedOutputReset>(
    rng: &mut T,
    blind: bool,
    priv_key: &RsaPrivateKey,
    hashed: &[u8],
    salt_len: usize,
) -> Result<Vec<u8>> {
    let mut salt = vec![0; salt_len];
    rng.fill_bytes(&mut salt[..]);

    sign_pss_with_salt_digest::<_, D>(blind.then_some(rng), priv_key, hashed, &salt)
}

/// signPSSWithSalt calculates the signature of hashed using PSS with specified salt.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. salt is a random sequence of bytes whose length will be
/// later used to verify the signature.
fn sign_pss_with_salt<T: CryptoRngCore>(
    blind_rng: Option<&mut T>,
    priv_key: &RsaPrivateKey,
    hashed: &[u8],
    salt: &[u8],
    digest: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let em_bits = priv_key.n().bits() - 1;
    let em = emsa_pss_encode(hashed, em_bits, salt, digest)?;

    uint_to_zeroizing_be_pad(
        priv_key.raw_int_decryption_primitive(blind_rng, &BigUint::from_bytes_be(&em))?,
        priv_key.size(),
    )
}

fn sign_pss_with_salt_digest<T: CryptoRngCore + ?Sized, D: Digest + FixedOutputReset>(
    blind_rng: Option<&mut T>,
    priv_key: &RsaPrivateKey,
    hashed: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>> {
    let em_bits = priv_key.n().bits() - 1;
    let em = emsa_pss_encode_digest::<D>(hashed, em_bits, salt)?;

    uint_to_zeroizing_be_pad(
        priv_key.raw_int_decryption_primitive(blind_rng, &BigUint::from_bytes_be(&em))?,
        priv_key.size(),
    )
}

/// Signing key for producing RSASSA-PSS signatures as described in
/// [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug, Clone)]
pub struct SigningKey<D>
where
    D: Digest,
{
    inner: RsaPrivateKey,
    salt_len: usize,
    phantom: PhantomData<D>,
}

impl<D> SigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS signing key with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Generate a new random RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Generate a new random RSASSA-PSS signing key with a salt of the given length.
    pub fn random_with_salt_len<R: CryptoRngCore + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        salt_len: usize,
    ) -> Result<Self> {
        Ok(Self {
            inner: RsaPrivateKey::new(rng, bit_size)?,
            salt_len,
            phantom: Default::default(),
        })
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

fn get_pss_signature_algo_id<D>(salt_len: u8) -> pkcs8::spki::Result<AlgorithmIdentifierOwned>
where
    D: Digest + AssociatedOid,
{
    const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

    let pss_params = RsaPssParams::new::<D>(salt_len);

    Ok(AlgorithmIdentifierOwned {
        oid: ID_RSASSA_PSS,
        parameters: Some(Any::encode_from(&pss_params)?),
    })
}

impl<D> AssociatedAlgorithmIdentifier for SigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

impl<D> DynSignatureAlgorithmIdentifier for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> pkcs8::spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
}

impl<D> From<RsaPrivateKey> for SigningKey<D>
where
    D: Digest,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<SigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: SigningKey<D>) -> Self {
        key.inner
    }
}

impl<D> EncodePrivateKey for SigningKey<D>
where
    D: Digest,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.inner.to_pkcs8_der()
    }
}

impl<D> Keypair for SigningKey<D>
where
    D: Digest,
{
    type VerifyingKey = VerifyingKey<D>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "getrandom")]
impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        self.try_sign_with_rng(&mut OsRng, msg)
    }
}

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, &D::digest(msg), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        digest: D,
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, &digest.finalize(), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedPrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, prehash, self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> AsRef<RsaPrivateKey> for SigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

/// Signing key for producing "blinded" RSASSA-PSS signatures as described in
/// [draft-irtf-cfrg-rsa-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/).
#[derive(Debug, Clone)]
pub struct BlindedSigningKey<D>
where
    D: Digest,
{
    inner: RsaPrivateKey,
    salt_len: usize,
    phantom: PhantomData<D>,
}

impl<D> BlindedSigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn random_with_salt_len<R: CryptoRngCore + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        salt_len: usize,
    ) -> Result<Self> {
        Ok(Self {
            inner: RsaPrivateKey::new(rng, bit_size)?,
            salt_len,
            phantom: Default::default(),
        })
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

impl<D> AssociatedAlgorithmIdentifier for BlindedSigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

impl<D> DynSignatureAlgorithmIdentifier for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> pkcs8::spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
}

impl<D> From<RsaPrivateKey> for BlindedSigningKey<D>
where
    D: Digest,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<BlindedSigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: BlindedSigningKey<D>) -> Self {
        key.inner
    }
}

impl<D> EncodePrivateKey for BlindedSigningKey<D>
where
    D: Digest,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.inner.to_pkcs8_der()
    }
}

impl<D> Keypair for BlindedSigningKey<D>
where
    D: Digest,
{
    type VerifyingKey = VerifyingKey<D>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

impl<D> RandomizedSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, true, &self.inner, &D::digest(msg), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        digest: D,
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, true, &self.inner, &digest.finalize(), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedPrehashSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, true, &self.inner, prehash, self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> AsRef<RsaPrivateKey> for BlindedSigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

/// Verifying key for checking the validity of RSASSA-PSS signatures as
/// described in [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug)]
pub struct VerifyingKey<D>
where
    D: Digest,
{
    inner: RsaPublicKey,
    salt_len: usize,
    phantom: PhantomData<D>,
}

/* Implemented manually so we don't have to bind D with Clone */
impl<D> Clone for VerifyingKey<D>
where
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

impl<D> VerifyingKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS verifying key.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPublicKey) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS verifying key.
    pub fn new_with_salt_len(key: RsaPublicKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }
}

impl<D> AssociatedAlgorithmIdentifier for VerifyingKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

impl<D> From<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: RsaPublicKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<VerifyingKey<D>> for RsaPublicKey
where
    D: Digest,
{
    fn from(key: VerifyingKey<D>) -> Self {
        key.inner
    }
}

impl<D> Verifier<Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> signature::Result<()> {
        verify_digest::<D>(
            &self.inner,
            &D::digest(msg),
            &signature.inner,
            signature.len,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> signature::Result<()> {
        verify_digest::<D>(
            &self.inner,
            &digest.finalize(),
            &signature.inner,
            signature.len,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

impl<D> PrehashVerifier<Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> signature::Result<()> {
        verify_digest::<D>(
            &self.inner,
            prehash,
            &signature.inner,
            signature.len,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

impl<D> AsRef<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPublicKey {
        &self.inner
    }
}

impl<D> EncodePublicKey for VerifyingKey<D>
where
    D: Digest,
{
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        self.inner.to_public_key_der()
    }
}

#[cfg(test)]
mod test {
    use crate::pss::{BlindedSigningKey, Pss, Signature, SigningKey, VerifyingKey};
    use crate::{RsaPrivateKey, RsaPublicKey};

    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::{FromPrimitive, Num};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use sha1::{Digest, Sha1};
    use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
    use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner, Verifier};

    fn get_private_key() -> RsaPrivateKey {
        // In order to generate new test vectors you'll need the PEM form of this key:
        // -----BEGIN RSA PRIVATE KEY-----
        // MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
        // fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
        // /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
        // RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
        // EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
        // IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
        // tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
        // -----END RSA PRIVATE KEY-----

        RsaPrivateKey::from_components(
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from_u64(65537).unwrap(),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            vec![
                BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443",10).unwrap(),
                BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap()
            ],
        ).unwrap()
    }

    #[test]
    fn test_verify_pss() {
        let priv_key = get_private_key();

        let tests = [
            (
                "test\n",
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
                ),
                true,
            ),
            (
                "test\n",
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();

        for (text, sig, expected) in &tests {
            let digest = Sha1::digest(text.as_bytes()).to_vec();
            let result = pub_key.verify(Pss::new::<Sha1>(), &digest, sig);
            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[test]
    fn test_verify_pss_signer() {
        let priv_key = get_private_key();

        let tests = [
            (
                "test\n",
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
                ),
                true,
            ),
            (
                "test\n",
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key: VerifyingKey<Sha1> = VerifyingKey::new(pub_key);

        for (text, sig, expected) in &tests {
            let result = verifying_key.verify(
                text.as_bytes(),
                &Signature::try_from(sig.as_slice()).unwrap(),
            );
            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[test]
    fn test_verify_pss_digest_signer() {
        let priv_key = get_private_key();

        let tests = [
            (
                "test\n",
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
                ),
                true,
            ),
            (
                "test\n",
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key = VerifyingKey::new(pub_key);

        for (text, sig, expected) in &tests {
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());
            let result =
                verifying_key.verify_digest(digest, &Signature::try_from(sig.as_slice()).unwrap());
            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let rng = ChaCha8Rng::from_seed([42; 32]);

        for test in &tests {
            let digest = Sha1::digest(test.as_bytes()).to_vec();
            let sig = priv_key
                .sign_with_rng(&mut rng.clone(), Pss::new::<Sha1>(), &digest)
                .expect("failed to sign");

            priv_key
                .verify(Pss::new::<Sha1>(), &digest, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_blinded_and_verify_roundtrip() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let rng = ChaCha8Rng::from_seed([42; 32]);

        for test in &tests {
            let digest = Sha1::digest(test.as_bytes()).to_vec();
            let sig = priv_key
                .sign_with_rng(&mut rng.clone(), Pss::new_blinded::<Sha1>(), &digest)
                .expect("failed to sign");

            priv_key
                .verify(Pss::new::<Sha1>(), &digest, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip_signer() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        for test in &tests {
            let sig = signing_key.sign_with_rng(&mut rng, test.as_bytes());
            verifying_key
                .verify(test.as_bytes(), &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip_blinded_signer() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = BlindedSigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        for test in &tests {
            let sig = signing_key.sign_with_rng(&mut rng, test.as_bytes());
            verifying_key
                .verify(test.as_bytes(), &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip_digest_signer() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        for test in &tests {
            let mut digest = Sha1::new();
            digest.update(test.as_bytes());
            let sig = signing_key.sign_digest_with_rng(&mut rng, digest);

            let mut digest = Sha1::new();
            digest.update(test.as_bytes());
            verifying_key
                .verify_digest(digest, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip_blinded_digest_signer() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = BlindedSigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        for test in &tests {
            let mut digest = Sha1::new();
            digest.update(test.as_bytes());
            let sig = signing_key.sign_digest_with_rng(&mut rng, digest);

            let mut digest = Sha1::new();
            digest.update(test.as_bytes());
            verifying_key
                .verify_digest(digest, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_verify_pss_hazmat() {
        let priv_key = get_private_key();

        let tests = [
            (
                Sha1::digest("test\n"),
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
                ),
                true,
            ),
            (
                Sha1::digest("test\n"),
                hex!(
                    "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
                    "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key = VerifyingKey::<Sha1>::new(pub_key);

        for (text, sig, expected) in &tests {
            let result = verifying_key
                .verify_prehash(text.as_ref(), &Signature::try_from(sig.as_slice()).unwrap());
            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[test]
    fn test_sign_and_verify_pss_hazmat() {
        let priv_key = get_private_key();

        let tests = [Sha1::digest("test\n")];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        for test in &tests {
            let sig = signing_key
                .sign_prehash_with_rng(&mut rng, &test)
                .expect("failed to sign");
            verifying_key
                .verify_prehash(&test, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_pss_blinded_hazmat() {
        let priv_key = get_private_key();

        let tests = [Sha1::digest("test\n")];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = BlindedSigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        for test in &tests {
            let sig = signing_key
                .sign_prehash_with_rng(&mut rng, &test)
                .expect("failed to sign");
            verifying_key
                .verify_prehash(&test, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    // Tests the corner case where the key is multiple of 8 + 1 bits long
    fn test_sign_and_verify_2049bit_key() {
        let plaintext = "Hello\n";
        let rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = RsaPrivateKey::new(&mut rng.clone(), 2049).unwrap();

        let digest = Sha1::digest(plaintext.as_bytes()).to_vec();
        let sig = priv_key
            .sign_with_rng(&mut rng.clone(), Pss::new::<Sha1>(), &digest)
            .expect("failed to sign");

        priv_key
            .verify(Pss::new::<Sha1>(), &digest, &sig)
            .expect("failed to verify");
    }
}
