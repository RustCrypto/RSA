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

use alloc::vec::Vec;

use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use core::marker::PhantomData;
use core::ops::Deref;
use digest::{Digest, DynDigest, FixedOutputReset};
use pkcs8::{Document, EncodePrivateKey, EncodePublicKey, SecretDocument};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "hazmat")]
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use signature::{
    DigestVerifier, RandomizedDigestSigner, RandomizedSigner, Signature as SignSignature, Verifier,
};
use subtle::ConstantTimeEq;

use crate::algorithms::{mgf1_xor, mgf1_xor_digest};
use crate::errors::{Error, Result};
use crate::key::{PrivateKey, PublicKey};
use crate::{RsaPrivateKey, RsaPublicKey};

/// RSASSA-PSS signatures as described in [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Clone)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> signature::Result<Self> {
        Ok(Signature {
            bytes: bytes.into(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Signature {}

impl Debug for Signature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        fmt.debug_list().entries(self.as_bytes().iter()).finish()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl LowerHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
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

pub(crate) fn verify<PK: PublicKey>(
    pub_key: &PK,
    hashed: &[u8],
    sig: &[u8],
    digest: &mut dyn DynDigest,
) -> Result<()> {
    if sig.len() != pub_key.size() {
        return Err(Error::Verification);
    }

    let em_bits = pub_key.n().bits() - 1;
    let em_len = (em_bits + 7) / 8;
    let mut em = pub_key.raw_encryption_primitive(sig, em_len)?;

    emsa_pss_verify(hashed, &mut em, em_bits, None, digest)
}

pub(crate) fn verify_digest<PK, D>(pub_key: &PK, hashed: &[u8], sig: &[u8]) -> Result<()>
where
    PK: PublicKey,
    D: Digest + FixedOutputReset,
{
    if sig.len() != pub_key.size() {
        return Err(Error::Verification);
    }

    let em_bits = pub_key.n().bits() - 1;
    let em_len = (em_bits + 7) / 8;
    let mut em = pub_key.raw_encryption_primitive(sig, em_len)?;

    emsa_pss_verify_digest::<D>(hashed, &mut em, em_bits, None)
}

/// SignPSS calculates the signature of hashed using RSASSA-PSS.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. The opts argument may be nil, in which case sensible
/// defaults are used.
// TODO: bind T with the CryptoRng trait
pub(crate) fn sign<T: RngCore + CryptoRng, SK: PrivateKey>(
    rng: &mut T,
    blind: bool,
    priv_key: &SK,
    hashed: &[u8],
    salt_len: Option<usize>,
    digest: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let salt = generate_salt(rng, priv_key, salt_len, digest.output_size());

    sign_pss_with_salt(blind.then(|| rng), priv_key, hashed, &salt, digest)
}

pub(crate) fn sign_digest<T: RngCore + CryptoRng, SK: PrivateKey, D: Digest + FixedOutputReset>(
    rng: &mut T,
    blind: bool,
    priv_key: &SK,
    hashed: &[u8],
    salt_len: Option<usize>,
) -> Result<Vec<u8>> {
    let salt = generate_salt(rng, priv_key, salt_len, <D as Digest>::output_size());

    sign_pss_with_salt_digest::<_, _, D>(blind.then(|| rng), priv_key, hashed, &salt)
}

fn generate_salt<T: RngCore + ?Sized, SK: PrivateKey>(
    rng: &mut T,
    priv_key: &SK,
    salt_len: Option<usize>,
    digest_size: usize,
) -> Vec<u8> {
    let salt_len = salt_len.unwrap_or_else(|| priv_key.size() - 2 - digest_size);

    let mut salt = vec![0; salt_len];
    rng.fill_bytes(&mut salt[..]);

    salt
}

/// signPSSWithSalt calculates the signature of hashed using PSS with specified salt.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. salt is a random sequence of bytes whose length will be
/// later used to verify the signature.
fn sign_pss_with_salt<T: CryptoRng + RngCore, SK: PrivateKey>(
    blind_rng: Option<&mut T>,
    priv_key: &SK,
    hashed: &[u8],
    salt: &[u8],
    digest: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    let em_bits = priv_key.n().bits() - 1;
    let em = emsa_pss_encode(hashed, em_bits, salt, digest)?;

    priv_key.raw_decryption_primitive(blind_rng, &em, priv_key.size())
}

fn sign_pss_with_salt_digest<
    T: CryptoRng + RngCore,
    SK: PrivateKey,
    D: Digest + FixedOutputReset,
>(
    blind_rng: Option<&mut T>,
    priv_key: &SK,
    hashed: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>> {
    let em_bits = priv_key.n().bits() - 1;
    let em = emsa_pss_encode_digest::<D>(hashed, em_bits, salt)?;

    priv_key.raw_decryption_primitive(blind_rng, &em, priv_key.size())
}

fn emsa_pss_encode(
    m_hash: &[u8],
    em_bits: usize,
    salt: &[u8],
    hash: &mut dyn DynDigest,
) -> Result<Vec<u8>> {
    // See [1], section 9.1.1
    let h_len = hash.output_size();
    let s_len = salt.len();
    let em_len = (em_bits + 7) / 8;

    // 1. If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "message too
    //     long" and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if m_hash.len() != h_len {
        return Err(Error::InputNotHashed);
    }

    // 3. If em_len < h_len + s_len + 2, output "encoding error" and stop.
    if em_len < h_len + s_len + 2 {
        // TODO: Key size too small
        return Err(Error::Internal);
    }

    let mut em = vec![0; em_len];

    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..(em_len - 1) - db.len()];

    // 4. Generate a random octet string salt of length s_len; if s_len = 0,
    //     then salt is the empty string.
    //
    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || m_hash || salt;
    //
    //     M' is an octet string of length 8 + h_len + s_len with eight
    //     initial zero octets.
    //
    // 6.  Let H = Hash(M'), an octet string of length h_len.
    let prefix = [0u8; 8];

    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);

    let hashed = hash.finalize_reset();
    h.copy_from_slice(&hashed);

    // 7.  Generate an octet string PS consisting of em_len - s_len - h_len - 2
    //     zero octets. The length of PS may be 0.
    //
    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.
    db[em_len - s_len - h_len - 2] = 0x01;
    db[em_len - s_len - h_len - 1..].copy_from_slice(salt);

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    //
    // 10. Let maskedDB = DB \xor dbMask.
    mgf1_xor(db, hash, h);

    // 11. Set the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //     maskedDB to zero.
    db[0] &= 0xFF >> (8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xBC;

    Ok(em)
}

fn emsa_pss_encode_digest<D>(m_hash: &[u8], em_bits: usize, salt: &[u8]) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset,
{
    // See [1], section 9.1.1
    let h_len = <D as Digest>::output_size();
    let s_len = salt.len();
    let em_len = (em_bits + 7) / 8;

    // 1. If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "message too
    //     long" and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if m_hash.len() != h_len {
        return Err(Error::InputNotHashed);
    }

    // 3. If em_len < h_len + s_len + 2, output "encoding error" and stop.
    if em_len < h_len + s_len + 2 {
        // TODO: Key size too small
        return Err(Error::Internal);
    }

    let mut em = vec![0; em_len];

    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..(em_len - 1) - db.len()];

    // 4. Generate a random octet string salt of length s_len; if s_len = 0,
    //     then salt is the empty string.
    //
    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || m_hash || salt;
    //
    //     M' is an octet string of length 8 + h_len + s_len with eight
    //     initial zero octets.
    //
    // 6.  Let H = Hash(M'), an octet string of length h_len.
    let prefix = [0u8; 8];

    let mut hash = D::new();

    Digest::update(&mut hash, &prefix);
    Digest::update(&mut hash, m_hash);
    Digest::update(&mut hash, salt);

    let hashed = hash.finalize_reset();
    h.copy_from_slice(&hashed);

    // 7.  Generate an octet string PS consisting of em_len - s_len - h_len - 2
    //     zero octets. The length of PS may be 0.
    //
    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.
    db[em_len - s_len - h_len - 2] = 0x01;
    db[em_len - s_len - h_len - 1..].copy_from_slice(salt);

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    //
    // 10. Let maskedDB = DB \xor dbMask.
    mgf1_xor_digest(db, &mut hash, h);

    // 11. Set the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //     maskedDB to zero.
    db[0] &= 0xFF >> (8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xBC;

    Ok(em)
}

fn emsa_pss_verify_pre<'a>(
    m_hash: &[u8],
    em: &'a mut [u8],
    em_bits: usize,
    s_len: Option<usize>,
    h_len: usize,
) -> Result<(&'a mut [u8], &'a mut [u8])> {
    // 1. If the length of M is greater than the input limitation for the
    //    hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    //    and stop.
    //
    // 2. Let mHash = Hash(M), an octet string of length hLen
    if m_hash.len() != h_len {
        return Err(Error::Verification);
    }

    // 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    let em_len = em.len(); //(em_bits + 7) / 8;
    if em_len < h_len + s_len.unwrap_or_default() + 2 {
        return Err(Error::Verification);
    }

    // 4. If the rightmost octet of EM does not have hexadecimal value
    //    0xbc, output "inconsistent" and stop.
    if em[em.len() - 1] != 0xBC {
        return Err(Error::Verification);
    }

    // 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //    let H be the next hLen octets.
    let (db, h) = em.split_at_mut(em_len - h_len - 1);
    let h = &mut h[..h_len];

    // 6. If the leftmost 8 * em_len - em_bits bits of the leftmost octet in
    //    maskedDB are not all equal to zero, output "inconsistent" and
    //    stop.
    if db[0] & (0xFF << /*uint*/(8 - (8 * em_len - em_bits))) != 0 {
        return Err(Error::Verification);
    }

    Ok((db, h))
}

fn emsa_pss_get_salt(
    db: &[u8],
    em_len: usize,
    s_len: Option<usize>,
    h_len: usize,
) -> Result<&[u8]> {
    let s_len = match s_len {
        None => (0..=em_len - (h_len + 2))
            .rev()
            .try_fold(None, |state, i| match (state, db[em_len - h_len - i - 2]) {
                (Some(i), _) => Ok(Some(i)),
                (_, 1) => Ok(Some(i)),
                (_, 0) => Ok(None),
                _ => Err(Error::Verification),
            })?
            .ok_or(Error::Verification)?,
        Some(s_len) => {
            // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
            //     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
            //     position is "position 1") does not have hexadecimal value 0x01,
            //     output "inconsistent" and stop.
            let (zeroes, rest) = db.split_at(em_len - h_len - s_len - 2);
            if zeroes.iter().any(|e| *e != 0x00) || rest[0] != 0x01 {
                return Err(Error::Verification);
            }

            s_len
        }
    };

    // 11. Let salt be the last s_len octets of DB.
    let salt = &db[db.len() - s_len..];

    Ok(salt)
}

fn emsa_pss_verify(
    m_hash: &[u8],
    em: &mut [u8],
    em_bits: usize,
    s_len: Option<usize>,
    hash: &mut dyn DynDigest,
) -> Result<()> {
    let em_len = em.len(); //(em_bits + 7) / 8;
    let h_len = hash.output_size();

    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;

    // 7. Let dbMask = MGF(H, em_len - h_len - 1)
    //
    // 8. Let DB = maskedDB \xor dbMask
    mgf1_xor(db, hash, &*h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= 0xFF >> /*uint*/(8 * em_len - em_bits);

    let salt = emsa_pss_get_salt(db, em_len, s_len, h_len)?;

    // 12. Let
    //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 13. Let H' = Hash(M'), an octet string of length hLen.
    let prefix = [0u8; 8];

    hash.update(&prefix[..]);
    hash.update(m_hash);
    hash.update(salt);
    let h0 = hash.finalize_reset();

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if h0.ct_eq(h).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

fn emsa_pss_verify_digest<D>(
    m_hash: &[u8],
    em: &mut [u8],
    em_bits: usize,
    s_len: Option<usize>,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let em_len = em.len(); //(em_bits + 7) / 8;
    let h_len = <D as Digest>::output_size();

    let (db, h) = emsa_pss_verify_pre(m_hash, em, em_bits, s_len, h_len)?;

    let mut hash = D::new();

    // 7. Let dbMask = MGF(H, em_len - h_len - 1)
    //
    // 8. Let DB = maskedDB \xor dbMask
    mgf1_xor_digest::<D>(db, &mut hash, &*h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= 0xFF >> /*uint*/(8 * em_len - em_bits);

    let salt = emsa_pss_get_salt(db, em_len, s_len, h_len)?;

    // 12. Let
    //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 13. Let H' = Hash(M'), an octet string of length hLen.
    let prefix = [0u8; 8];

    Digest::update(&mut hash, &prefix[..]);
    Digest::update(&mut hash, m_hash);
    Digest::update(&mut hash, salt);
    let h0 = hash.finalize_reset();

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if h0.ct_eq(h).into() {
        Ok(())
    } else {
        Err(Error::Verification)
    }
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
    salt_len: Option<usize>,
    phantom: PhantomData<D>,
}

impl<D> SigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            salt_len: None,
            phantom: Default::default(),
        }
    }

    /// Create a new RSASSA-PSS signing key with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len: Some(salt_len),
            phantom: Default::default(),
        }
    }

    pub(crate) fn key(&self) -> &RsaPrivateKey {
        &self.inner
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

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, _, D>(&mut rng, false, &self.inner, &D::digest(msg), self.salt_len)
            .map(|v| v.into())
            .map_err(|e| e.into())
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> signature::Result<Signature> {
        sign_digest::<_, _, D>(
            &mut rng,
            false,
            &self.inner,
            &digest.finalize(),
            self.salt_len,
        )
        .map(|v| v.into())
        .map_err(|e| e.into())
    }
}

#[cfg(feature = "hazmat")]
impl<D> RandomizedPrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, _, D>(&mut rng, false, &self.inner, prehash, self.salt_len)
            .map(|v| v.into())
            .map_err(|e| e.into())
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
    salt_len: Option<usize>,
    phantom: PhantomData<D>,
}

impl<D> BlindedSigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            salt_len: None,
            phantom: Default::default(),
        }
    }

    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len: Some(salt_len),
            phantom: Default::default(),
        }
    }

    pub(crate) fn key(&self) -> &RsaPrivateKey {
        &self.inner
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

impl<D> RandomizedSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, _, D>(&mut rng, true, &self.inner, &D::digest(msg), self.salt_len)
            .map(|v| v.into())
            .map_err(|e| e.into())
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> signature::Result<Signature> {
        sign_digest::<_, _, D>(
            &mut rng,
            true,
            &self.inner,
            &digest.finalize(),
            self.salt_len,
        )
        .map(|v| v.into())
        .map_err(|e| e.into())
    }
}

#[cfg(feature = "hazmat")]
impl<D> RandomizedPrehashSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, _, D>(&mut rng, true, &self.inner, prehash, self.salt_len)
            .map(|v| v.into())
            .map_err(|e| e.into())
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
#[derive(Debug, Clone)]
pub struct VerifyingKey<D>
where
    D: Digest,
{
    inner: RsaPublicKey,
    phantom: PhantomData<D>,
}

impl<D> VerifyingKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS verifying key.
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            phantom: Default::default(),
        }
    }
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

impl<D> From<SigningKey<D>> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: SigningKey<D>) -> Self {
        Self {
            inner: key.key().into(),
            phantom: Default::default(),
        }
    }
}

impl<D> From<&SigningKey<D>> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: &SigningKey<D>) -> Self {
        Self {
            inner: key.key().into(),
            phantom: Default::default(),
        }
    }
}

impl<D> From<BlindedSigningKey<D>> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: BlindedSigningKey<D>) -> Self {
        Self {
            inner: key.key().into(),
            phantom: Default::default(),
        }
    }
}

impl<D> From<&BlindedSigningKey<D>> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: &BlindedSigningKey<D>) -> Self {
        Self {
            inner: key.key().into(),
            phantom: Default::default(),
        }
    }
}

impl<D> Verifier<Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> signature::Result<()> {
        verify_digest::<_, D>(&self.inner, &D::digest(msg), signature.as_ref())
            .map_err(|e| e.into())
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> signature::Result<()> {
        verify_digest::<_, D>(&self.inner, &digest.finalize(), signature.as_ref())
            .map_err(|e| e.into())
    }
}

#[cfg(feature = "hazmat")]
impl<D> PrehashVerifier<Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> signature::Result<()> {
        verify_digest::<_, D>(&self.inner, prehash, signature.as_ref()).map_err(|e| e.into())
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
    use crate::pss::{BlindedSigningKey, SigningKey, VerifyingKey};
    use crate::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::{FromPrimitive, Num};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use sha1::{Digest, Sha1};
    #[cfg(feature = "hazmat")]
    use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
    use signature::{
        DigestVerifier, RandomizedDigestSigner, RandomizedSigner, Signature, Verifier,
    };

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
            let result = pub_key.verify(PaddingScheme::new_pss::<Sha1>(), &digest, sig);
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
            let result =
                verifying_key.verify(text.as_bytes(), &Signature::from_bytes(sig).unwrap());
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
            let result = verifying_key.verify_digest(digest, &Signature::from_bytes(sig).unwrap());
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
                .sign_with_rng(&mut rng.clone(), PaddingScheme::new_pss::<Sha1>(), &digest)
                .expect("failed to sign");

            priv_key
                .verify(PaddingScheme::new_pss::<Sha1>(), &digest, &sig)
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
                .sign_blinded(&mut rng.clone(), PaddingScheme::new_pss::<Sha1>(), &digest)
                .expect("failed to sign");

            priv_key
                .verify(PaddingScheme::new_pss::<Sha1>(), &digest, &sig)
                .expect("failed to verify");
        }
    }

    #[test]
    fn test_sign_and_verify_roundtrip_signer() {
        let priv_key = get_private_key();

        let tests = ["test\n"];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let verifying_key = VerifyingKey::from(&signing_key);

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
        let verifying_key = VerifyingKey::from(&signing_key);

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
        let verifying_key = VerifyingKey::from(&signing_key);

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
        let verifying_key = VerifyingKey::from(&signing_key);

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

    #[cfg(feature = "hazmat")]
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
            let result =
                verifying_key.verify_prehash(text.as_ref(), &Signature::from_bytes(sig).unwrap());
            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_sign_and_verify_pss_hazmat() {
        let priv_key = get_private_key();

        let tests = [Sha1::digest("test\n")];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let verifying_key = VerifyingKey::from(&signing_key);

        for test in &tests {
            let sig = signing_key
                .sign_prehash_with_rng(&mut rng, &test)
                .expect("failed to sign");
            verifying_key
                .verify_prehash(&test, &sig)
                .expect("failed to verify");
        }
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_sign_and_verify_pss_blinded_hazmat() {
        let priv_key = get_private_key();

        let tests = [Sha1::digest("test\n")];
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = BlindedSigningKey::<Sha1>::new(priv_key);
        let verifying_key = VerifyingKey::from(&signing_key);

        for test in &tests {
            let sig = signing_key
                .sign_prehash_with_rng(&mut rng, &test)
                .expect("failed to sign");
            verifying_key
                .verify_prehash(&test, &sig)
                .expect("failed to verify");
        }
    }
}
