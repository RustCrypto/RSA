//! PKCS#1 OAEP support as described in [RFC8017 § 7.1].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#oaep-encryption).
//!
//! [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use rand_core::CryptoRngCore;

use digest::{Digest, FixedOutputReset};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroizing;

use crate::algorithms::mgf1_xor_digest;
use crate::dummy_rng::DummyRng;
use crate::errors::{Error, Result};
use crate::key::{self, PrivateKey, PublicKey};
use crate::traits::{Decryptor, RandomizedDecryptor, RandomizedEncryptor};
use crate::{RsaPrivateKey, RsaPublicKey};

// 2**61 -1 (pow is not const yet)
// TODO: This is the maximum for SHA-1, unclear from the RFC what the values are for other hashing functions.
const MAX_LABEL_LEN: u64 = 2_305_843_009_213_693_951;

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub fn encrypt<
    R: CryptoRngCore + ?Sized,
    K: PublicKey,
    D: Digest,
    MGD: Digest + FixedOutputReset,
>(
    rng: &mut R,
    pub_key: &K,
    msg: &[u8],
    label: Option<String>,
) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let k = pub_key.size();

    let h_size = <D as Digest>::output_size();

    if msg.len() + 2 * h_size + 2 > k {
        return Err(Error::MessageTooLong);
    }

    let label = label.unwrap_or_default();
    if label.len() as u64 > MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let mut em = Zeroizing::new(vec![0u8; k]);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);
    rng.fill_bytes(seed);

    // Data block DB =  pHash || PS || 01 || M
    let db_len = k - h_size - 1;

    let p_hash = D::digest(label.as_bytes());
    db[0..h_size].copy_from_slice(&*p_hash);
    db[db_len - msg.len() - 1] = 1;
    db[db_len - msg.len()..].copy_from_slice(msg);

    let mut mgf_digest = MGD::new();
    mgf1_xor_digest(db, &mut mgf_digest, seed);
    mgf1_xor_digest(seed, &mut mgf_digest, db);

    pub_key.raw_encryption_primitive(&em, pub_key.size())
}

/// Decrypts a plaintext using RSA and the padding scheme from [PKCS#1 OAEP].
///
/// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key.
///
/// See `decrypt_session_key` for a way of solving this problem.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub fn decrypt<
    R: CryptoRngCore + ?Sized,
    SK: PrivateKey,
    D: Digest,
    MGD: Digest + FixedOutputReset,
>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
    label: Option<String>,
) -> Result<Vec<u8>> {
    key::check_public(priv_key)?;

    let res = decrypt_inner::<_, _, D, MGD>(rng, priv_key, ciphertext, label)?;
    if res.is_none().into() {
        return Err(Error::Decryption);
    }

    let (out, index) = res.unwrap();

    Ok(out[index as usize..].to_vec())
}

/// Decrypts ciphertext using `priv_key` and blinds the operation if
/// `rng` is given. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured.
#[inline]
fn decrypt_inner<
    R: CryptoRngCore + ?Sized,
    SK: PrivateKey,
    D: Digest,
    MGD: Digest + FixedOutputReset,
>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
    label: Option<String>,
) -> Result<CtOption<(Vec<u8>, u32)>> {
    let k = priv_key.size();
    if k < 11 {
        return Err(Error::Decryption);
    }

    let h_size = <D as Digest>::output_size();

    if ciphertext.len() != k || k < h_size * 2 + 2 {
        return Err(Error::Decryption);
    }

    let mut em = priv_key.raw_decryption_primitive(rng, ciphertext, priv_key.size())?;

    let label = label.unwrap_or_default();
    if label.len() as u64 > MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    let expected_p_hash = D::digest(label.as_bytes());

    let first_byte_is_zero = em[0].ct_eq(&0u8);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);

    let mut mgf_digest = MGD::new();
    mgf1_xor_digest(seed, &mut mgf_digest, db);
    mgf1_xor_digest(db, &mut mgf_digest, seed);

    let hash_are_equal = db[0..h_size].ct_eq(expected_p_hash.as_slice());

    // The remainder of the plaintext must be zero or more 0x00, followed
    // by 0x01, followed by the message.
    //   looking_for_index: 1 if we are still looking for the 0x01
    //   index: the offset of the first 0x01 byte
    //   zero_before_one: 1 if we saw a non-zero byte before the 1
    let mut looking_for_index = Choice::from(1u8);
    let mut index = 0u32;
    let mut nonzero_before_one = Choice::from(0u8);

    for (i, el) in db.iter().skip(h_size).enumerate() {
        let equals0 = el.ct_eq(&0u8);
        let equals1 = el.ct_eq(&1u8);
        index.conditional_assign(&(i as u32), looking_for_index & equals1);
        looking_for_index &= !equals1;
        nonzero_before_one |= looking_for_index & !equals0;
    }

    let valid = first_byte_is_zero & hash_are_equal & !nonzero_before_one & !looking_for_index;

    Ok(CtOption::new((em, index + 2 + (h_size * 2) as u32), valid))
}

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
pub struct EncryptingKey<D, MGD = D>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    inner: RsaPublicKey,
    label: Option<String>,
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

impl<D, MGD> EncryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    pub fn new_with_label<S: AsRef<str>>(key: RsaPublicKey, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.as_ref().to_string()),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<D, MGD> RandomizedEncryptor for EncryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn encrypt_with_rng<R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt::<_, _, D, MGD>(rng, &self.inner, msg, self.label.as_ref().cloned())
    }
}

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
pub struct DecryptingKey<D, MGD = D>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    inner: RsaPrivateKey,
    label: Option<String>,
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

impl<D, MGD> DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    pub fn new_with_label<S: AsRef<str>>(key: RsaPrivateKey, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.as_ref().to_string()),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<D, MGD> Decryptor for DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt::<DummyRng, _, D, MGD>(None, &self.inner, ciphertext, self.label.as_ref().cloned())
    }
}

impl<D, MGD> RandomizedDecryptor for DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn decrypt_with_rng<R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt::<_, _, D, MGD>(
            Some(rng),
            &self.inner,
            ciphertext,
            self.label.as_ref().cloned(),
        )
    }
}
