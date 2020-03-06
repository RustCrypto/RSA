use std::fmt;

use digest::{Digest, DynDigest};

/// Available padding schemes.
#[derive(Clone)]
pub enum PaddingScheme {
    PKCS1v15,
    OAEP {
        digest: Box<dyn DynDigest>,
        label: Option<String>,
    },
    PSS,
}

impl fmt::Debug for PaddingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaddingScheme::PKCS1v15 => write!(f, "PaddingScheme::PKCS1v15"),
            PaddingScheme::OAEP { ref label, .. } => {
                // TODO: How to print the digest name?
                write!(f, "PaddingScheme::OAEP({:?})", label)
            }
            PaddingScheme::PSS => write!(f, "PaddingScheme::PSS"),
        }
    }
}

impl PaddingScheme {
    pub fn new_pkcs1v15() -> Self {
        PaddingScheme::PKCS1v15
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

    pub fn new_pss() -> Self {
        PaddingScheme::PSS
    }
}
