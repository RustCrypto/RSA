use std::fmt;

use digest::{Digest, DynDigest};
use rand::RngCore;

use crate::hash::Hash;

/// Available padding schemes.
pub enum PaddingScheme {
    PKCS1v15 {
        hash: Option<Hash>,
    },
    OAEP {
        digest: Box<dyn DynDigest>,
        label: Option<String>,
    },
    PSS {
        salt_rng: Box<dyn RngCore>,
        digest: Box<dyn DynDigest>,
        salt_len: Option<usize>,
    },
}

impl fmt::Debug for PaddingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaddingScheme::PKCS1v15 { ref hash } => {
                write!(f, "PaddingScheme::PKCS1v15({:?})", hash)
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
    pub fn new_pkcs1v15() -> Self {
        PaddingScheme::PKCS1v15 { hash: None }
    }

    pub fn new_pkcs1v15_with_hash(hash: Hash) -> Self {
        PaddingScheme::PKCS1v15 { hash: Some(hash) }
    }

    pub fn new_oaep<T: 'static + Digest + DynDigest>() -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
            label: None,
        }
    }

    pub fn new_oaep_with_label<T: 'static + Digest + DynDigest, S: AsRef<str>>(label: S) -> Self {
        PaddingScheme::OAEP {
            digest: Box::new(T::new()),
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
