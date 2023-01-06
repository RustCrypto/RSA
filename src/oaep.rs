use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use rand_core::CryptoRngCore;

use digest::{Digest, DynDigest};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroizing;

use crate::algorithms::mgf1_xor;
use crate::errors::{Error, Result};
use crate::key::{self, PrivateKey, PublicKey};
use crate::padding::PaddingScheme;

// 2**61 -1 (pow is not const yet)
// TODO: This is the maximum for SHA-1, unclear from the RFC what the values are for other hashing functions.
const MAX_LABEL_LEN: u64 = 2_305_843_009_213_693_951;

/// Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
///
/// - `digest` is used to hash the label. The maximum possible plaintext length is `m = k - 2 * h_len - 2`,
///   where `k` is the size of the RSA modulus.
/// - `mgf_digest` specifies the hash function that is used in the [MGF1](https://datatracker.ietf.org/doc/html/rfc8017#appendix-B.2).
/// - `label` is optional data that can be associated with the message.
///
/// The two hash functions can, but don't need to be the same.
///
/// A prominent example is the [`AndroidKeyStore`](https://developer.android.com/guide/topics/security/cryptography#oaep-mgf1-digest).
/// It uses SHA-1 for `mgf_digest` and a user-chosen SHA flavour for `digest`.
pub struct Oaep {
    /// Digest type to use.
    pub digest: Box<dyn DynDigest + Send + Sync>,

    /// Digest to use for Mask Generation Function (MGF).
    pub mgf_digest: Box<dyn DynDigest + Send + Sync>,

    /// Optional label.
    pub label: Option<String>,
}

impl Oaep {
    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for both the default (empty) label and for MGF1.
    ///
    /// # Example
    /// ```
    /// use sha1::Sha1;
    /// use sha2::Sha256;
    /// use rsa::{BigUint, RsaPublicKey, Oaep, PublicKey};
    /// use base64ct::{Base64, Encoding};
    ///
    /// let n = Base64::decode_vec("ALHgDoZmBQIx+jTmgeeHW6KsPOrj11f6CvWsiRleJlQpW77AwSZhd21ZDmlTKfaIHBSUxRUsuYNh7E2SHx8rkFVCQA2/gXkZ5GK2IUbzSTio9qXA25MWHvVxjMfKSL8ZAxZyKbrG94FLLszFAFOaiLLY8ECs7g+dXOriYtBwLUJK+lppbd+El+8ZA/zH0bk7vbqph5pIoiWggxwdq3mEz4LnrUln7r6dagSQzYErKewY8GADVpXcq5mfHC1xF2DFBub7bFjMVM5fHq7RK+pG5xjNDiYITbhLYrbVv3X0z75OvN0dY49ITWjM7xyvMWJXVJS7sJlgmCCL6RwWgP8PhcE=").unwrap();
    /// let e = Base64::decode_vec("AQAB").unwrap();
    ///
    /// let mut rng = rand::thread_rng();
    /// let key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
    /// let padding = Oaep::new::<Sha256>();
    /// let encrypted_data = key.encrypt(&mut rng, padding, b"secret").unwrap();
    /// ```
    pub fn new<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for both the label and for MGF1.
    pub fn new_with_label<T: 'static + Digest + DynDigest + Send + Sync, S: AsRef<str>>(
        label: S,
    ) -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: Some(label.as_ref().to_string()),
        }
    }

    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for the default (empty) label, and `U` as the hash function for MGF1.
    /// If a label is needed use `PaddingScheme::new_oaep_with_label` or `PaddingScheme::new_oaep_with_mgf_hash_with_label`.
    ///
    /// # Example
    /// ```
    /// use sha1::Sha1;
    /// use sha2::Sha256;
    /// use rsa::{BigUint, RsaPublicKey, Oaep, PublicKey};
    /// use base64ct::{Base64, Encoding};
    ///
    /// let n = Base64::decode_vec("ALHgDoZmBQIx+jTmgeeHW6KsPOrj11f6CvWsiRleJlQpW77AwSZhd21ZDmlTKfaIHBSUxRUsuYNh7E2SHx8rkFVCQA2/gXkZ5GK2IUbzSTio9qXA25MWHvVxjMfKSL8ZAxZyKbrG94FLLszFAFOaiLLY8ECs7g+dXOriYtBwLUJK+lppbd+El+8ZA/zH0bk7vbqph5pIoiWggxwdq3mEz4LnrUln7r6dagSQzYErKewY8GADVpXcq5mfHC1xF2DFBub7bFjMVM5fHq7RK+pG5xjNDiYITbhLYrbVv3X0z75OvN0dY49ITWjM7xyvMWJXVJS7sJlgmCCL6RwWgP8PhcE=").unwrap();
    /// let e = Base64::decode_vec("AQAB").unwrap();
    ///
    /// let mut rng = rand::thread_rng();
    /// let key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
    /// let padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
    /// let encrypted_data = key.encrypt(&mut rng, padding, b"secret").unwrap();
    /// ```
    pub fn new_with_mgf_hash<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
    >() -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for the label, and `U` as the hash function for MGF1.
    pub fn new_with_mgf_hash_and_label<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: Some(label.as_ref().to_string()),
        }
    }
}

impl PaddingScheme for Oaep {
    fn decrypt<Rng: CryptoRngCore, Priv: PrivateKey>(
        mut self,
        rng: Option<&mut Rng>,
        priv_key: &Priv,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt(
            rng,
            priv_key,
            ciphertext,
            &mut *self.digest,
            &mut *self.mgf_digest,
            self.label,
        )
    }

    fn encrypt<Rng: CryptoRngCore, Pub: PublicKey>(
        mut self,
        rng: &mut Rng,
        pub_key: &Pub,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt(
            rng,
            pub_key,
            msg,
            &mut *self.digest,
            &mut *self.mgf_digest,
            self.label,
        )
    }
}

impl fmt::Debug for Oaep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAEP")
            .field("digest", &"...")
            .field("mgf_digest", &"...")
            .field("label", &self.label)
            .finish()
    }
}

/// Encrypts the given message with RSA and the padding scheme from
/// [PKCS#1 OAEP].
///
/// The message must be no longer than the length of the public modulus minus
/// `2 + (2 * hash.size())`.
///
/// [PKCS#1 OAEP]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[inline]
pub fn encrypt<R: CryptoRngCore + ?Sized, K: PublicKey>(
    rng: &mut R,
    pub_key: &K,
    msg: &[u8],
    digest: &mut dyn DynDigest,
    mgf_digest: &mut dyn DynDigest,
    label: Option<String>,
) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let k = pub_key.size();

    let h_size = digest.output_size();

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

    digest.update(label.as_bytes());
    let p_hash = digest.finalize_reset();
    db[0..h_size].copy_from_slice(&p_hash);
    db[db_len - msg.len() - 1] = 1;
    db[db_len - msg.len()..].copy_from_slice(msg);

    mgf1_xor(db, mgf_digest, seed);
    mgf1_xor(seed, mgf_digest, db);

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
pub fn decrypt<R: CryptoRngCore + ?Sized, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
    digest: &mut dyn DynDigest,
    mgf_digest: &mut dyn DynDigest,
    label: Option<String>,
) -> Result<Vec<u8>> {
    key::check_public(priv_key)?;

    let res = decrypt_inner(rng, priv_key, ciphertext, digest, mgf_digest, label)?;
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
fn decrypt_inner<R: CryptoRngCore + ?Sized, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
    digest: &mut dyn DynDigest,
    mgf_digest: &mut dyn DynDigest,
    label: Option<String>,
) -> Result<CtOption<(Vec<u8>, u32)>> {
    let k = priv_key.size();
    if k < 11 {
        return Err(Error::Decryption);
    }

    let h_size = digest.output_size();

    if ciphertext.len() != k || k < h_size * 2 + 2 {
        return Err(Error::Decryption);
    }

    let mut em = priv_key.raw_decryption_primitive(rng, ciphertext, priv_key.size())?;

    let label = label.unwrap_or_default();
    if label.len() as u64 > MAX_LABEL_LEN {
        return Err(Error::LabelTooLong);
    }

    digest.update(label.as_bytes());

    let expected_p_hash = &*digest.finalize_reset();

    let first_byte_is_zero = em[0].ct_eq(&0u8);

    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(h_size);

    mgf1_xor(seed, mgf_digest, db);
    mgf1_xor(db, mgf_digest, seed);

    let hash_are_equal = db[0..h_size].ct_eq(expected_p_hash);

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
