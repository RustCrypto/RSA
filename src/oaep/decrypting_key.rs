use super::decrypt_digest;
use crate::{
    dummy_rng::DummyRng,
    traits::{Decryptor, RandomizedDecryptor},
    Result, RsaPrivateKey,
};
use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::CryptoRng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Decryption key for PKCS#1 v1.5 decryption as described in [RFC8017 § 7.1].
///
/// [RFC8017 § 7.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecryptingKey<D, MGD = D>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    inner: RsaPrivateKey,
    label: Option<Box<[u8]>>,
    phantom: PhantomData<D>,
    mg_phantom: PhantomData<MGD>,
}

impl<D, MGD> DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            label: None,
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }

    /// Create a new verifying key from an RSA public key using provided label
    pub fn new_with_label<S: Into<Box<[u8]>>>(key: RsaPrivateKey, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.into()),
            phantom: Default::default(),
            mg_phantom: Default::default(),
        }
    }
}

impl<D, MGD> Decryptor for DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_digest::<DummyRng, D, MGD>(None, &self.inner, ciphertext, self.label.clone())
    }
}

impl<D, MGD> RandomizedDecryptor for DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn decrypt_with_rng<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt_digest::<_, D, MGD>(Some(rng), &self.inner, ciphertext, self.label.clone())
    }
}

impl<D, MGD> ZeroizeOnDrop for DecryptingKey<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
}

impl<D, MGD> PartialEq for DecryptingKey<D, MGD>
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
        use sha2::Sha256;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let decrypting_key = DecryptingKey::<Sha256>::new(
            RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key"),
        );

        let tokens = [
            Token::Struct {
                name: "DecryptingKey",
                len: 4,
            },
            Token::Str("inner"),
            Token::Str(concat!(
                "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100cf823bdbad23cda55787e9d1dbd630457e3e8407f3a4da723656a120866a8284ce211ff8464904cf7dab256d0b5544549719f4155d32187ad3eb928ada9cd4152a9e4153e21c68022e654b0d10b065519e9ef5619f431740c2a0f568141c27670485f28d1643fe650af3757f4775af5d01ed3c992a6269c5aa5ff7f52450c30a84783e36931b8855b091559540ec34e0730c511d62e09ea86d66b0f4cb92d1a609e7fb6f34ae8cf08bd791eee85150850e943fb5e4d9b7fd44a5eb474ed7e0bb7faa2e1dca443d5df8f77468fb0905731e421b2e06e864f957f3a517b2b0e3ad09118310b9fd74cb54bb07308d009e3ec6cecc17f06cddf10e0b1b9eff5ff8b90203010001028201000a7071d4765c63bf1aad32bd25031c80927e50a419c4c45c94913d1fe6c33af7b56b0331b94f79177b29fe03035bf1c913a4f19b9589aca3993fb3aa9a9ee32881715eb5fa9d153a6edd17ae7b9574336bf8713dcd065208270273f61d74e122949eac7a1e91a31db0345947e2ef6fb80d1dc33bad5f30150aa2335638d27b4d57f47262b31059351b08c2350d8afe88d1dfbd1b398daf317db8c0cd42859072b8ddadcc2d50c5ad1d6d06a56594bdabb7dd51c77fe2b5d404c64ff99e6500de5da418c5c49c6ebd7ecfc400f18ba26fd4d6e7b31e435d494326585a9efff7bdb3c51ba19399918df4a999453dfed65e84adb15b0a183416b5ec5f221491978102818100e148067566a1fa3aabd0672361be62715516c9d62790b03f4326cc00b2f782e6b64a167689e5c9aebe6a4cf594f3083380fe2a0a7edf1f325e58c523b9819747a90ad93c4b19bb40807391b5a9404ce5ea359e7b0556ee25cb2e7455aeb5caf83fc26f34457cdbb173347962c66b6fe0c4686b54dbe0d2c913a7aa924eff6ec902818100ebcdd03d9b1dfd2ea4f2d6dade79fcb02727d84426f9d756121525f14696434fa594867ca839d1025b823a7576eb6c8b33e6dd4ff4fcb72c6069d1e5e74885e90b76b0bf3994501dd0ef212694e73cbf43855731ba543c771debf979eea8f77fcab8a53d56fc46d5398893f3421ca54b371afb10ecb2137892f5062c506e82710281801c345542ab87c9f9407b85fe23059ff38a70a0f263dfb481271a1b5e5709afe4cc9bb7f63d4b7c9599175bed3f29b234288929a048c40c76d4e30e436bbd32c071047fb011c2f5f39c615bb3bfade232c2c0d5c797228c0c4544daa1c38ed50b8188093e2518fdb458b5102172b00ec0b8364e81c049847a5230a2a550a8a029028180718bebc89e9734416fc057e190dbe0e7da12ffbae1a1d1256b13afef9cf3e279c9dbd95ed18af5b052ec44c6277b7a0b15f50780e711820ae66a4e5e8c9e898d0cae1cb21841e8ca52bfb390e686eae396d9f080cb9ea077237b6be8611a10040354228d85037a0056f2037c51cb8574d096376b90eeb71d8a765e809c427aa102818100886afe7a9610e60cd2da4cf3137ba5f597cd9cdc344f36c4101720363341c42cdfe09f68ee25a3dd63e191b6542bcd97aaa0af776eb68aaab84db4594e5340591b4fe194ea2fe2f7586ac3c3aaf8bc337963c4e05d6556b1a6024ac6e07710cdf01bcd9543e263a35ad13baaa2aa6c3af60880cc56622959916cab038a51fff9",
            )),
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
        assert_tokens(&decrypting_key.readable(), &tokens);
    }
}
