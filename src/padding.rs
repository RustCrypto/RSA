//! Supported padding schemes.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::fmt;

use digest::{Digest, DynDigest};
use pkcs8::AssociatedOid;

use crate::pkcs1v15;

/// Available padding schemes.
pub enum PaddingScheme {
    /// Encryption and Decryption using PKCS1v15 padding.
    PKCS1v15Encrypt,

    /// Sign and Verify using PKCS1v15 padding.
    PKCS1v15Sign {
        /// Length of hash to use.
        hash_len: Option<usize>,

        /// Prefix.
        prefix: Box<[u8]>,
    },

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
    OAEP {
        /// Digest type to use.
        digest: Box<dyn DynDigest + Send + Sync>,

        /// Digest to use for Mask Generation Function (MGF).
        mgf_digest: Box<dyn DynDigest + Send + Sync>,

        /// Optional label.
        label: Option<String>,
    },

    /// Sign and Verify using PSS padding.
    PSS {
        /// Digest type to use.
        digest: Box<dyn DynDigest + Send + Sync>,

        /// Salt length.
        salt_len: Option<usize>,
    },
}

impl fmt::Debug for PaddingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaddingScheme::PKCS1v15Encrypt => write!(f, "PaddingScheme::PKCS1v15Encrypt"),
            PaddingScheme::PKCS1v15Sign { prefix, .. } => {
                write!(f, "PaddingScheme::PKCS1v15Sign({:?})", prefix)
            }
            PaddingScheme::OAEP { ref label, .. } => {
                // TODO: How to print the digest name?
                write!(f, "PaddingScheme::OAEP({:?})", label)
            }
            PaddingScheme::PSS { ref salt_len, .. } => {
                // TODO: How to print the digest name?
                write!(f, "PaddingScheme::PSS(salt_len: {:?})", salt_len)
            }
        }
    }
}

impl PaddingScheme {
    /// Create new PKCS#1 v1.5 encryption padding.
    pub fn new_pkcs1v15_encrypt() -> Self {
        PaddingScheme::PKCS1v15Encrypt
    }

    /// Create new PKCS#1 v1.5 padding for computing a raw signature.
    ///
    /// This sets `hash_len` to `None` and uses an empty `prefix`.
    pub fn new_pkcs1v15_sign_raw() -> Self {
        PaddingScheme::PKCS1v15Sign {
            hash_len: None,
            prefix: Box::new([]),
        }
    }

    /// Create new PKCS#1 v1.5 padding for the given digest.
    ///
    /// The digest must have an [`AssociatedOid`]. Make sure to enable the `oid`
    /// feature of the relevant digest crate.
    pub fn new_pkcs1v15_sign<D>() -> Self
    where
        D: Digest + AssociatedOid,
    {
        PaddingScheme::PKCS1v15Sign {
            hash_len: Some(<D as Digest>::output_size()),
            prefix: pkcs1v15::generate_prefix::<D>().into_boxed_slice(),
        }
    }

    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for the default (empty) label, and `U` as the hash function for MGF1.
    /// If a label is needed use `PaddingScheme::new_oaep_with_label` or `PaddingScheme::new_oaep_with_mgf_hash_with_label`.
    ///
    /// # Example
    /// ```
    /// use sha1::Sha1;
    /// use sha2::Sha256;
    /// use rsa::{BigUint, RsaPublicKey, PaddingScheme, PublicKey};
    /// use base64ct::{Base64, Encoding};
    ///
    /// let n = Base64::decode_vec("ALHgDoZmBQIx+jTmgeeHW6KsPOrj11f6CvWsiRleJlQpW77AwSZhd21ZDmlTKfaIHBSUxRUsuYNh7E2SHx8rkFVCQA2/gXkZ5GK2IUbzSTio9qXA25MWHvVxjMfKSL8ZAxZyKbrG94FLLszFAFOaiLLY8ECs7g+dXOriYtBwLUJK+lppbd+El+8ZA/zH0bk7vbqph5pIoiWggxwdq3mEz4LnrUln7r6dagSQzYErKewY8GADVpXcq5mfHC1xF2DFBub7bFjMVM5fHq7RK+pG5xjNDiYITbhLYrbVv3X0z75OvN0dY49ITWjM7xyvMWJXVJS7sJlgmCCL6RwWgP8PhcE=").unwrap();
    /// let e = Base64::decode_vec("AQAB").unwrap();
    ///
    /// let mut rng = rand::thread_rng();
    /// let key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
    /// let padding = PaddingScheme::new_oaep_with_mgf_hash::<Sha256, Sha1>();
    /// let encrypted_data = key.encrypt(&mut rng, padding, b"secret").unwrap();
    /// ```
    pub fn new_oaep_with_mgf_hash<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
    >() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme`, using `T` as the hash function for both the default (empty) label and for MGF1.
    ///
    /// # Example
    /// ```
    /// use sha1::Sha1;
    /// use sha2::Sha256;
    /// use rsa::{BigUint, RsaPublicKey, PaddingScheme, PublicKey};
    /// use base64ct::{Base64, Encoding};
    ///
    /// let n = Base64::decode_vec("ALHgDoZmBQIx+jTmgeeHW6KsPOrj11f6CvWsiRleJlQpW77AwSZhd21ZDmlTKfaIHBSUxRUsuYNh7E2SHx8rkFVCQA2/gXkZ5GK2IUbzSTio9qXA25MWHvVxjMfKSL8ZAxZyKbrG94FLLszFAFOaiLLY8ECs7g+dXOriYtBwLUJK+lppbd+El+8ZA/zH0bk7vbqph5pIoiWggxwdq3mEz4LnrUln7r6dagSQzYErKewY8GADVpXcq5mfHC1xF2DFBub7bFjMVM5fHq7RK+pG5xjNDiYITbhLYrbVv3X0z75OvN0dY49ITWjM7xyvMWJXVJS7sJlgmCCL6RwWgP8PhcE=").unwrap();
    /// let e = Base64::decode_vec("AQAB").unwrap();
    ///
    /// let mut rng = rand::thread_rng();
    /// let key = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
    /// let padding = PaddingScheme::new_oaep::<Sha256>();
    /// let encrypted_data = key.encrypt(&mut rng, padding, b"secret").unwrap();
    /// ```
    pub fn new_oaep<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for the label, and `U` as the hash function for MGF1.
    pub fn new_oaep_with_mgf_hash_with_label<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: Some(label.as_ref().to_string()),
        }
    }

    /// Create a new OAEP `PaddingScheme` with an associated `label`, using `T` as the hash function for both the label and for MGF1.
    pub fn new_oaep_with_label<T: 'static + Digest + DynDigest + Send + Sync, S: AsRef<str>>(
        label: S,
    ) -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: Some(label.as_ref().to_string()),
        }
    }

    /// New PSS padding for the given digest.
    pub fn new_pss<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        PaddingScheme::PSS {
            digest: Box::new(T::new()),
            salt_len: None,
        }
    }

    /// New PSS padding for the given digest with a salt value of the given length.
    pub fn new_pss_with_salt<T: 'static + Digest + DynDigest + Send + Sync>(len: usize) -> Self {
        PaddingScheme::PSS {
            digest: Box::new(T::new()),
            salt_len: Some(len),
        }
    }
}
