use super::{sign_digest, Signature, VerifyingKey};
use crate::{Result, RsaPrivateKey};
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::{CryptoRng, TryCryptoRng};
use signature::{
    hazmat::RandomizedPrehashSigner, Keypair, RandomizedDigestSigner, RandomizedMultipartSigner,
    RandomizedSigner,
};
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "encoding")]
use {
    super::get_pss_signature_algo_id,
    const_oid::AssociatedOid,
    pkcs8::{EncodePrivateKey, SecretDocument},
    spki::{
        der::AnyRef, AlgorithmIdentifierOwned, AlgorithmIdentifierRef,
        AssociatedAlgorithmIdentifier, DynSignatureAlgorithmIdentifier,
    },
};
#[cfg(feature = "serde")]
use {
    pkcs8::DecodePrivateKey,
    serdect::serde::{de, ser, Deserialize, Serialize},
};

/// Signing key for producing "blinded" RSASSA-PSS signatures as described in
/// [draft-irtf-cfrg-rsa-blind-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/).
#[derive(Debug, Clone)]
pub struct BlindedSigningKey<D>
where
    D: Digest,
{
    inner: RsaPrivateKey,
    salt_len: usize,
    phantom: PhantomData<D>,
}

impl<D> BlindedSigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Create a new random RSASSA-PSS signing key which produces "blinded"
    /// signatures with a salt of the given length.
    pub fn random_with_salt_len<R: CryptoRng + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        salt_len: usize,
    ) -> Result<Self> {
        Ok(Self {
            inner: RsaPrivateKey::new(rng, bit_size)?,
            salt_len,
            phantom: Default::default(),
        })
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> usize {
        self.salt_len
    }
}

//
// `*Signer` trait impls
//

impl<D> RandomizedSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

impl<D> RandomizedMultipartSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> signature::Result<Signature> {
        let mut digest = D::new();
        msg.iter()
            .for_each(|slice| <D as Digest>::update(&mut digest, slice));
        sign_digest::<_, D>(rng, true, &self.inner, &digest.finalize(), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_digest_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        digest: D,
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, true, &self.inner, &digest.finalize(), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedPrehashSigner<Signature> for BlindedSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, true, &self.inner, prehash, self.salt_len)?
            .as_slice()
            .try_into()
    }
}

//
// Other trait impls
//

impl<D> AsRef<RsaPrivateKey> for BlindedSigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

#[cfg(feature = "encoding")]
impl<D> AssociatedAlgorithmIdentifier for BlindedSigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

#[cfg(feature = "encoding")]
impl<D> DynSignatureAlgorithmIdentifier for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
}

#[cfg(feature = "encoding")]
impl<D> EncodePrivateKey for BlindedSigningKey<D>
where
    D: Digest,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.inner.to_pkcs8_der()
    }
}

impl<D> From<RsaPrivateKey> for BlindedSigningKey<D>
where
    D: Digest,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<BlindedSigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: BlindedSigningKey<D>) -> Self {
        key.inner
    }
}

impl<D> Keypair for BlindedSigningKey<D>
where
    D: Digest,
{
    type VerifyingKey = VerifyingKey<D>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            salt_len: Some(self.salt_len),
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "encoding")]
impl<D> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        RsaPrivateKey::try_from(private_key_info).map(Self::new)
    }
}

impl<D> ZeroizeOnDrop for BlindedSigningKey<D> where D: Digest {}

impl<D> PartialEq for BlindedSigningKey<D>
where
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
    }
}

#[cfg(feature = "serde")]
impl<D> Serialize for BlindedSigningKey<D>
where
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self.to_pkcs8_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der.as_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, D> Deserialize<'de> for BlindedSigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn deserialize<De>(deserializer: De) -> core::result::Result<Self, De::Error>
    where
        De: serde::Deserializer<'de>,
    {
        let der_bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::from_pkcs8_der(&der_bytes).map_err(de::Error::custom)
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
        let signing_key = BlindedSigningKey::<Sha256>::new(
            RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key"),
        );

        let tokens = [Token::Str(concat!(
            "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100cf823bdbad23cda55787e9d1dbd630457e3e8407f3a4da723656a120866a8284ce211ff8464904cf7dab256d0b5544549719f4155d32187ad3eb928ada9cd4152a9e4153e21c68022e654b0d10b065519e9ef5619f431740c2a0f568141c27670485f28d1643fe650af3757f4775af5d01ed3c992a6269c5aa5ff7f52450c30a84783e36931b8855b091559540ec34e0730c511d62e09ea86d66b0f4cb92d1a609e7fb6f34ae8cf08bd791eee85150850e943fb5e4d9b7fd44a5eb474ed7e0bb7faa2e1dca443d5df8f77468fb0905731e421b2e06e864f957f3a517b2b0e3ad09118310b9fd74cb54bb07308d009e3ec6cecc17f06cddf10e0b1b9eff5ff8b90203010001028201000a7071d4765c63bf1aad32bd25031c80927e50a419c4c45c94913d1fe6c33af7b56b0331b94f79177b29fe03035bf1c913a4f19b9589aca3993fb3aa9a9ee32881715eb5fa9d153a6edd17ae7b9574336bf8713dcd065208270273f61d74e122949eac7a1e91a31db0345947e2ef6fb80d1dc33bad5f30150aa2335638d27b4d57f47262b31059351b08c2350d8afe88d1dfbd1b398daf317db8c0cd42859072b8ddadcc2d50c5ad1d6d06a56594bdabb7dd51c77fe2b5d404c64ff99e6500de5da418c5c49c6ebd7ecfc400f18ba26fd4d6e7b31e435d494326585a9efff7bdb3c51ba19399918df4a999453dfed65e84adb15b0a183416b5ec5f221491978102818100e148067566a1fa3aabd0672361be62715516c9d62790b03f4326cc00b2f782e6b64a167689e5c9aebe6a4cf594f3083380fe2a0a7edf1f325e58c523b9819747a90ad93c4b19bb40807391b5a9404ce5ea359e7b0556ee25cb2e7455aeb5caf83fc26f34457cdbb173347962c66b6fe0c4686b54dbe0d2c913a7aa924eff6ec902818100ebcdd03d9b1dfd2ea4f2d6dade79fcb02727d84426f9d756121525f14696434fa594867ca839d1025b823a7576eb6c8b33e6dd4ff4fcb72c6069d1e5e74885e90b76b0bf3994501dd0ef212694e73cbf43855731ba543c771debf979eea8f77fcab8a53d56fc46d5398893f3421ca54b371afb10ecb2137892f5062c506e82710281801c345542ab87c9f9407b85fe23059ff38a70a0f263dfb481271a1b5e5709afe4cc9bb7f63d4b7c9599175bed3f29b234288929a048c40c76d4e30e436bbd32c071047fb011c2f5f39c615bb3bfade232c2c0d5c797228c0c4544daa1c38ed50b8188093e2518fdb458b5102172b00ec0b8364e81c049847a5230a2a550a8a029028180718bebc89e9734416fc057e190dbe0e7da12ffbae1a1d1256b13afef9cf3e279c9dbd95ed18af5b052ec44c6277b7a0b15f50780e711820ae66a4e5e8c9e898d0cae1cb21841e8ca52bfb390e686eae396d9f080cb9ea077237b6be8611a10040354228d85037a0056f2037c51cb8574d096376b90eeb71d8a765e809c427aa102818100886afe7a9610e60cd2da4cf3137ba5f597cd9cdc344f36c4101720363341c42cdfe09f68ee25a3dd63e191b6542bcd97aaa0af776eb68aaab84db4594e5340591b4fe194ea2fe2f7586ac3c3aaf8bc337963c4e05d6556b1a6024ac6e07710cdf01bcd9543e263a35ad13baaa2aa6c3af60880cc56622959916cab038a51fff9",
        ))];
        assert_tokens(&signing_key.readable(), &tokens);
    }
}
