use super::encrypt;
use crate::{traits::RandomizedEncryptor, Result, RsaPublicKey};
use alloc::vec::Vec;
use rand_core::CryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptingKey {
    pub(super) inner: RsaPublicKey,
}

impl EncryptingKey {
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey) -> Self {
        Self { inner: key }
    }
}

impl RandomizedEncryptor for EncryptingKey {
    fn encrypt_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        encrypt(rng, &self.inner, msg)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use serde_test::{assert_tokens, Configure, Token};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate key");
        let encrypting_key = EncryptingKey::new(priv_key.to_public_key());

        let tokens = [
            Token::Struct {
                name: "EncryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(concat!(
                "30819f300d06092a864886f70d010101050003818d0030818902818100cd1419dc3771354bee",
                "0955a90489cce0c98aee6577851358afe386a68bc95287862a1157d5aba8847e8e57b6f2f947",
                "48ab7efda3f3c74a6702329397ffe0b1d4f76e1b025d87d583e48b3cfce99d6a507d94eb46c5",
                "242b3addb54d346ecf43eb0d7343bcb258a31d5fa51f47b9e0d7280623901d1d29af1a986fec",
                "92ba5fe2430203010001",
            )),
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.clone().readable(), &tokens);
    }
}
