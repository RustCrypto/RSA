use super::{decrypt, EncryptingKey};
use crate::{
    dummy_rng::DummyRng,
    traits::{Decryptor, EncryptingKeypair, RandomizedDecryptor},
    Result, RsaPrivateKey,
};
use alloc::vec::Vec;
use rand_core::CryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.2].
///
/// [RFC8017 § 7.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.2
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecryptingKey {
    inner: RsaPrivateKey,
}

impl DecryptingKey {
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self { inner: key }
    }
}

impl Decryptor for DecryptingKey {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt::<DummyRng>(None, &self.inner, ciphertext)
    }
}

impl RandomizedDecryptor for DecryptingKey {
    fn decrypt_with_rng<R: CryptoRng + ?Sized>(
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
    #[cfg(feature = "serde")]
    fn test_serde() {
        use super::*;
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use serde_test::{assert_tokens, Configure, Token};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let decrypting_key =
            DecryptingKey::new(RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate key"));

        let tokens = [
            Token::Struct {
                name: "DecryptingKey",
                len: 1,
            },
            Token::Str("inner"),
            Token::Str(concat!(
                "30820278020100300d06092a864886f70d0101010500048202623082025e0",
                "2010002818100cd1419dc3771354bee0955a90489cce0c98aee6577851358",
                "afe386a68bc95287862a1157d5aba8847e8e57b6f2f94748ab7efda3f3c74",
                "a6702329397ffe0b1d4f76e1b025d87d583e48b3cfce99d6a507d94eb46c5",
                "242b3addb54d346ecf43eb0d7343bcb258a31d5fa51f47b9e0d7280623901",
                "d1d29af1a986fec92ba5fe2430203010001028181009bb3203326d0c7b31f",
                "456d08c6ce4c8379e10640792ecad271afe002406d184096a707c5d50ee00",
                "1c00818266970c3233439551f0e2d879a8f7b90bd3d62fdffa3e661f14c8d",
                "cce071f081966e25bb351289810c2f8a012f2fa3f001029d7f2e0cf24f6a4",
                "b139292f8078fac24e7fc8185bab4f02f539267bd09b615e4e19fe1024100",
                "e90ad93c4b19bb40807391b5a9404ce5ea359e7b0556ee25cb2e7455aeb5c",
                "af83fc26f34457cdbb173347962c66b6fe0c4686b54dbe0d2c913a7aa924e",
                "ff6031024100e148067566a1fa3aabd0672361be62715516c9d62790b03f4",
                "326cc00b2f782e6b64a167689e5c9aebe6a4cf594f3083380fe2a0a7edf1f",
                "325e58c523b981a0b3024100ab96e85323bd038a3fca588c58ddd681278d6",
                "96e8d84ef7ef676f303afcb7d728287e897a55e84e8c8b9e772da447b3115",
                "8d0912877fa7d4945b4d15c382f7d102400ddde317e2e36185af01baf7809",
                "2b97884664cb233e9421002d0268a7c79a3c313c167b4903466bfacd4da3b",
                "db99420df988ab89cdd96a102da2852ff7c134e5024100bafb0dac0fda53f",
                "9c755c23483343922727b88a5256a6fb47242e1c99b8f8a2c914f39f7af30",
                "1219245786a6bb15336231d6a9b57ee7e0b3dd75129f93f54ecf"
            )),
            Token::StructEnd,
        ];
        assert_tokens(&decrypting_key.readable(), &tokens);
    }
}
