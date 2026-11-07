use super::{EncryptingKey, decrypt};
#[cfg(not(feature = "getrandom"))]
use crate::dummy_rng::DummyRng;
use crate::{
    PrivateKey, Result,
    traits::{Decryptor, EncryptingKeypair, RandomizedDecryptor},
};
use alloc::vec::Vec;
use rand_core::TryCryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.2].
///
/// Invalid padding returns deterministic synthetic plaintext using the implicit rejection algorithm
/// documented on [`super::Pkcs1v15Encrypt`]. Successful decryption does not establish message
/// authenticity.
///
/// [`Decryptor::decrypt`] uses the operating system RNG for blinding when the `getrandom`
/// feature is enabled (the default). Otherwise, use [`RandomizedDecryptor::decrypt_with_rng`]
/// to supply an RNG for blinding.
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecryptingKey {
    inner: PrivateKey,
}

impl DecryptingKey {
    /// Create a new decryption key from an RSA private key.
    #[must_use]
    pub fn new(key: PrivateKey) -> Self {
        Self { inner: key }
    }
}

impl Decryptor for DecryptingKey {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "getrandom")]
        {
            decrypt(
                Some(&mut crypto_common::getrandom::SysRng),
                &self.inner,
                ciphertext,
            )
        }
        #[cfg(not(feature = "getrandom"))]
        {
            decrypt::<DummyRng>(None, &self.inner, ciphertext)
        }
    }
}

impl RandomizedDecryptor for DecryptingKey {
    fn decrypt_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt(Some(rng), &self.inner, ciphertext)
    }
}

impl EncryptingKeypair for DecryptingKey {
    type EncryptingKey = EncryptingKey;
    fn encrypting_key(&self) -> EncryptingKey {
        EncryptingKey {
            inner: self.inner.clone().into(),
        }
    }
}

impl ZeroizeOnDrop for DecryptingKey {}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "hazmat", feature = "serde"))]
    fn test_serde() {
        use super::*;
        use rand::rngs::ChaCha8Rng;
        use rand_core::SeedableRng;
        use serde_test::{Configure, Token, assert_tokens};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let decrypting_key = DecryptingKey::new(
            PrivateKey::new_unchecked(&mut rng, 64).expect("failed to generate key"),
        );

        let tokens = [
            Token::Struct {
                name: "DecryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(concat!(
                "3056020100300d06092a864886f70d010101050004423040020100020900ab",
                "240c3361d02e370203010001020811e54a15259d22f9020500ceff5cf30205",
                "00d3a7aaad020500ccaddf17020500cb529d3d020500bb526d6f"
            )),
            Token::StructEnd,
        ];
        assert_tokens(&decrypting_key.readable(), &tokens);
    }
}
