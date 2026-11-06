use super::encrypt;
use crate::{PublicKey, Result, traits::RandomizedEncryptor};
use alloc::vec::Vec;
use rand_core::TryCryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptingKey {
    pub(super) inner: PublicKey,
}

impl EncryptingKey {
    /// Create a new verifying key from an RSA public key.
    #[must_use]
    pub fn new(key: PublicKey) -> Self {
        Self { inner: key }
    }
}

impl RandomizedEncryptor for EncryptingKey {
    fn encrypt_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt(rng, &self.inner, msg)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use pkcs8::DecodePublicKey;
        use serde_test::{Configure, Token, assert_tokens};

        let der = include_bytes!("../../tests/examples/pkcs8/rsa2048-pub.der");
        let pub_key = PublicKey::from_public_key_der(der).unwrap();
        let encoded = include_str!("../../tests/examples/pkcs8/rsa2048-pub.hex").trim();
        let encrypting_key = EncryptingKey::new(pub_key);

        let tokens = [
            Token::Struct {
                name: "EncryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(encoded),
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.clone().readable(), &tokens);
    }
}
