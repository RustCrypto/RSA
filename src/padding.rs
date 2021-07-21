use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::fmt;

use digest::{Digest, DynDigest};
use rand::RngCore;

use crate::hash::Hash;

/// Available padding schemes.
pub enum PaddingScheme {
    /// Encryption and Decryption using PKCS1v15 padding.
    PKCS1v15Encrypt,
    /// Sign and Verify using PKCS1v15 padding.
    PKCS1v15Sign { hash: Option<Hash> },
    /// Encryption and Decryption using [OAEP padding](https://datatracker.ietf.org/doc/html/rfc3447#section-7.1.1).
    /// The OAEP padding scheme relays on a hash function `digest`, which fixes the output length of the various
    /// padding blocks and hence fixes the max length of the plain-text to be `m = n - 2 * h_len - 2`, where `n` is the size of the 
    /// modulus of the public key. Further, if a label is specified, it represents the hash function used to hash the label.
    /// On the other hand, to prevent chosen plain-text attacks, a mask generation function is used. For OAEP this 
    /// is [MGF1](https://datatracker.ietf.org/doc/html/rfc2437#section-10.2.1), which is a mask generation function
    /// based on a hash function `mgf_digest`. 
    /// 
    /// The two hash functions can, but don't need to be the same. A prominent example is the `AndroidKeyStore`, which
    /// uses a OAEP padding with `digest` being SHA-256 _but_ `mgf_digest` being SHA-1.
    OAEP {
        digest: Box<dyn DynDigest>,
        mgf_digest: Box<dyn DynDigest>,
        label: Option<String>,
    },
    /// Sign and Verify using PSS padding.
    PSS {
        salt_rng: Box<dyn RngCore>,
        digest: Box<dyn DynDigest>,
        salt_len: Option<usize>,
    },
}

impl fmt::Debug for PaddingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaddingScheme::PKCS1v15Encrypt => write!(f, "PaddingScheme::PKCS1v15Encrypt"),
            PaddingScheme::PKCS1v15Sign { ref hash } => {
                write!(f, "PaddingScheme::PKCS1v15Sign({:?})", hash)
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
    pub fn new_pkcs1v15_encrypt() -> Self {
        PaddingScheme::PKCS1v15Encrypt
    }

    pub fn new_pkcs1v15_sign(hash: Option<Hash>) -> Self {
        PaddingScheme::PKCS1v15Sign { hash }
    }

    /// Create a new OAEP `PaddingScheme`, using `T` for the OAEP hash function, and `U` for the MGF1 hash function.
    /// If a label is needed use `PaddingScheme::new_oaep_with_label` or `PaddingScheme::new_oaep_with_mgf_hash_with_label`.
    /// 
    /// # Example
    /// ```
    ///     use sha1::Sha1;
    ///     use sha2::Sha256;
    ///     use rand::rngs::OsRng;
    ///     use rsa::{BigUint, RSAPublicKey, PaddingScheme, PublicKey};

    ///     let n = base64::decode("ALHgDoZmBQIx+jTmgeeHW6KsPOrj11f6CvWsiRleJlQpW77AwSZhd21ZDmlTKfaIHBSUxRUsuYNh7E2SHx8rkFVCQA2/gXkZ5GK2IUbzSTio9qXA25MWHvVxjMfKSL8ZAxZyKbrG94FLLszFAFOaiLLY8ECs7g+dXOriYtBwLUJK+lppbd+El+8ZA/zH0bk7vbqph5pIoiWggxwdq3mEz4LnrUln7r6dagSQzYErKewY8GADVpXcq5mfHC1xF2DFBub7bFjMVM5fHq7RK+pG5xjNDiYITbhLYrbVv3X0z75OvN0dY49ITWjM7xyvMWJXVJS7sJlgmCCL6RwWgP8PhcE=").unwrap();
    ///     let e = base64::decode("AQAB").unwrap();
    ///     
    ///     let key = RSAPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
    ///     let padding = PaddingScheme::new_oaep_with_mgf_hash::<Sha256, Sha1>();
    ///     let encrypted_data = key.encrypt(&mut OsRng, padding, b"secret").unwrap();
    /// ```
    pub fn new_oaep_with_mgf_hash<
        T: 'static + Digest + DynDigest,
        U: 'static + Digest + DynDigest,
    >() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme` with the specified hash function.
    /// Further, the same hash function is used for the MGF1 mask generation function.
    /// 
    /// # Example
    /// ```
    ///     use sha1::Sha1;
    ///     use sha2::Sha256;
    ///     use rand::rngs::OsRng;
    ///     use rsa::{BigUint, RSAPublicKey, PaddingScheme, PublicKey};

    ///     let n = base64::decode("ALHgDoZmBQIx+jTmgeeHW6KsPOrj11f6CvWsiRleJlQpW77AwSZhd21ZDmlTKfaIHBSUxRUsuYNh7E2SHx8rkFVCQA2/gXkZ5GK2IUbzSTio9qXA25MWHvVxjMfKSL8ZAxZyKbrG94FLLszFAFOaiLLY8ECs7g+dXOriYtBwLUJK+lppbd+El+8ZA/zH0bk7vbqph5pIoiWggxwdq3mEz4LnrUln7r6dagSQzYErKewY8GADVpXcq5mfHC1xF2DFBub7bFjMVM5fHq7RK+pG5xjNDiYITbhLYrbVv3X0z75OvN0dY49ITWjM7xyvMWJXVJS7sJlgmCCL6RwWgP8PhcE=").unwrap();
    ///     let e = base64::decode("AQAB").unwrap();
    ///     
    ///     let key = RSAPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).unwrap();
    ///     let padding = PaddingScheme::new_oaep::<Sha256>();
    ///     let encrypted_data = key.encrypt(&mut OsRng, padding, b"secret").unwrap();
    /// ```
    pub fn new_oaep<T: 'static + Digest + DynDigest>() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: None,
        }
    }

    /// Create a new OAEP `PaddingScheme`, with `T` being the OAEP hash function and `U`
    /// being the hash function used for the MGF1 mask generation function. Note that `T`
    /// is also used to hash the label.
    pub fn new_oaep_with_mgf_hash_with_label<
        T: 'static + Digest + DynDigest,
        U: 'static + Digest + DynDigest,
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

    /// Create a new OAEP `PaddingScheme` with the specified hash function.
    /// The _same_ hash function will be used for hashing the label as well as
    /// for the mask generation function.
    pub fn new_oaep_with_label<T: 'static + Digest + DynDigest, S: AsRef<str>>(label: S) -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: Some(label.as_ref().to_string()),
        }
    }

    pub fn new_pss<T: 'static + Digest + DynDigest, S: 'static + RngCore>(rng: S) -> Self {
        PaddingScheme::PSS {
            salt_rng: Box::new(rng),
            digest: Box::new(T::new()),
            salt_len: None,
        }
    }

    pub fn new_pss_with_salt<T: 'static + Digest + DynDigest, S: 'static + RngCore>(
        rng: S,
        len: usize,
    ) -> Self {
        PaddingScheme::PSS {
            salt_rng: Box::new(rng),
            digest: Box::new(T::new()),
            salt_len: Some(len),
        }
    }
}
