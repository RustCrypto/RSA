use super::encrypt;
use crate::{traits::RandomizedEncryptor, Result, RsaPublicKey};
use alloc::vec::Vec;
use rand_core::CryptoRngCore;
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
    fn encrypt_with_rng<R: CryptoRngCore + ?Sized>(
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
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use serde_test::{assert_tokens, Configure, Token};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let encrypting_key = EncryptingKey::new(priv_key.to_public_key());

        let tokens = [
            Token::Struct {
                name: "EncryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(
                "3024300d06092a864886f70d01010105000313003010020900cc6c6130e35b46bf0203010001",
            ),
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.clone().readable(), &tokens);
    }
}
