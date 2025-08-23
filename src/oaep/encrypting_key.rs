use super::encrypt_digest;
use crate::{traits::RandomizedEncryptor, Result, RsaPublicKey};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::CryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Encryption key for PKCS#1 v1.5 encryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EncryptingKey<D, MGD = D>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    inner: RsaPublicKey,
    label: Option<Box<[u8]>>,
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

impl<D, MGD> EncryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    pub fn new_with_label<S: Into<Box<[u8]>>>(key: RsaPublicKey, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.into()),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<D, MGD> RandomizedEncryptor for EncryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn encrypt_with_rng<R: CryptoRng + ?Sized>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>> {
        encrypt_digest::<_, D, MGD>(rng, &self.inner, msg, self.label.clone())
    }
}

impl<D, MGD> PartialEq for EncryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.label == other.label
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
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
        let encrypting_key = EncryptingKey::<sha2::Sha256>::new(priv_key.to_public_key());

        let tokens = [
            Token::Struct {
                name: "EncryptingKey",
                len: 4,
            },
            Token::Str("inner"),
            Token::Str(
                "30820122300d06092a864886f70d01010105000382010f003082010a0282010100cf823bdbad23cda55787e9d1dbd630457e3e8407f3a4da723656a120866a8284ce211ff8464904cf7dab256d0b5544549719f4155d32187ad3eb928ada9cd4152a9e4153e21c68022e654b0d10b065519e9ef5619f431740c2a0f568141c27670485f28d1643fe650af3757f4775af5d01ed3c992a6269c5aa5ff7f52450c30a84783e36931b8855b091559540ec34e0730c511d62e09ea86d66b0f4cb92d1a609e7fb6f34ae8cf08bd791eee85150850e943fb5e4d9b7fd44a5eb474ed7e0bb7faa2e1dca443d5df8f77468fb0905731e421b2e06e864f957f3a517b2b0e3ad09118310b9fd74cb54bb07308d009e3ec6cecc17f06cddf10e0b1b9eff5ff8b90203010001",
            ),
            Token::Str("label"),
            Token::None,
            Token::Str("phantom"),
            Token::UnitStruct {
                name: "PhantomData",
            },
            Token::Str("mg_phantom"),
            Token::UnitStruct {
                name: "PhantomData",
            },
            Token::StructEnd,
        ];
        assert_tokens(&encrypting_key.readable(), &tokens);
    }
}
