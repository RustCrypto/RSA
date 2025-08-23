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
#[cfg(feature = "serde")]
use {
    pkcs8::DecodePrivateKey,
    serdect::serde::{de, ser, Deserialize, Serialize},
};

#[cfg(feature = "encoding")]
use {
    super::get_pss_signature_algo_id,
    crate::encoding::verify_algorithm_id,
    const_oid::AssociatedOid,
    pkcs8::{EncodePrivateKey, SecretDocument},
    spki::{
        der::AnyRef, AlgorithmIdentifierOwned, AlgorithmIdentifierRef,
        AssociatedAlgorithmIdentifier, DynSignatureAlgorithmIdentifier,
    },
};
#[cfg(feature = "os_rng")]
use {
    rand_core::OsRng,
    signature::{hazmat::PrehashSigner, MultipartSigner, Signer},
};

/// Signing key for producing RSASSA-PSS signatures as described in
/// [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug, Clone)]
pub struct SigningKey<D>
where
    D: Digest,
{
    inner: RsaPrivateKey,
    salt_len: usize,
    phantom: PhantomData<D>,
}

impl<D> SigningKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS signing key with a salt of the given length.
    pub fn new_with_salt_len(key: RsaPrivateKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len,
            phantom: Default::default(),
        }
    }

    /// Generate a new random RSASSA-PSS signing key.
    /// Digest output size is used as a salt length.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Generate a new random RSASSA-PSS signing key with a salt of the given length.
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

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_digest_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        digest: D,
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, &digest.finalize(), self.salt_len)?
            .as_slice()
            .try_into()
    }
}

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_sign_digest_with_rng(rng, D::new_with_prefix(msg))
    }
}

impl<D> RandomizedMultipartSigner<Signature> for SigningKey<D>
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
        self.try_sign_digest_with_rng(rng, digest)
    }
}

impl<D> RandomizedPrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, prehash, self.salt_len)?
            .as_slice()
            .try_into()
    }
}

#[cfg(feature = "os_rng")]
impl<D> PrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        self.sign_prehash_with_rng(&mut OsRng, prehash)
    }
}

#[cfg(feature = "os_rng")]
impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        self.try_sign_with_rng(&mut OsRng, msg)
    }
}

#[cfg(feature = "os_rng")]
impl<D> MultipartSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> signature::Result<Signature> {
        self.try_multipart_sign_with_rng(&mut OsRng, msg)
    }
}

//
// Other trait impls
//

impl<D> AsRef<RsaPrivateKey> for SigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

#[cfg(feature = "encoding")]
impl<D> AssociatedAlgorithmIdentifier for SigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

#[cfg(feature = "encoding")]
impl<D> DynSignatureAlgorithmIdentifier for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
}

#[cfg(feature = "encoding")]
impl<D> EncodePrivateKey for SigningKey<D>
where
    D: Digest,
{
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        self.inner.to_pkcs8_der()
    }
}

impl<D> From<RsaPrivateKey> for SigningKey<D>
where
    D: Digest,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<SigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: SigningKey<D>) -> Self {
        key.inner
    }
}

impl<D> Keypair for SigningKey<D>
where
    D: Digest,
{
    type VerifyingKey = VerifyingKey<D>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "encoding")]
impl<D> TryFrom<pkcs8::PrivateKeyInfoRef<'_>> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: pkcs8::PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        verify_algorithm_id(&private_key_info.algorithm)?;
        RsaPrivateKey::try_from(private_key_info).map(Self::new)
    }
}

impl<D> ZeroizeOnDrop for SigningKey<D> where D: Digest {}

impl<D> PartialEq for SigningKey<D>
where
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
    }
}

#[cfg(feature = "serde")]
impl<D> Serialize for SigningKey<D>
where
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serdect::serde::Serializer,
    {
        let der = self.to_pkcs8_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der.as_bytes(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, D> Deserialize<'de> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn deserialize<De>(deserializer: De) -> core::result::Result<Self, De::Error>
    where
        De: serdect::serde::Deserializer<'de>,
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
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate key");
        let signing_key = SigningKey::<Sha256>::new(priv_key);

        let tokens = [Token::Str(concat!(
            "30820278020100300d06092a864886f70d0101010500048202623082025e020100",
            "02818100cd1419dc3771354bee0955a90489cce0c98aee6577851358afe386a68b",
            "c95287862a1157d5aba8847e8e57b6f2f94748ab7efda3f3c74a6702329397ffe0",
            "b1d4f76e1b025d87d583e48b3cfce99d6a507d94eb46c5242b3addb54d346ecf43",
            "eb0d7343bcb258a31d5fa51f47b9e0d7280623901d1d29af1a986fec92ba5fe243",
            "0203010001028181009bb3203326d0c7b31f456d08c6ce4c8379e10640792ecad2",
            "71afe002406d184096a707c5d50ee001c00818266970c3233439551f0e2d879a8f",
            "7b90bd3d62fdffa3e661f14c8dcce071f081966e25bb351289810c2f8a012f2fa3",
            "f001029d7f2e0cf24f6a4b139292f8078fac24e7fc8185bab4f02f539267bd09b6",
            "15e4e19fe1024100e90ad93c4b19bb40807391b5a9404ce5ea359e7b0556ee25cb",
            "2e7455aeb5caf83fc26f34457cdbb173347962c66b6fe0c4686b54dbe0d2c913a7",
            "aa924eff6031024100e148067566a1fa3aabd0672361be62715516c9d62790b03f",
            "4326cc00b2f782e6b64a167689e5c9aebe6a4cf594f3083380fe2a0a7edf1f325e",
            "58c523b981a0b3024100ab96e85323bd038a3fca588c58ddd681278d696e8d84ef",
            "7ef676f303afcb7d728287e897a55e84e8c8b9e772da447b31158d0912877fa7d4",
            "945b4d15c382f7d102400ddde317e2e36185af01baf78092b97884664cb233e942",
            "1002d0268a7c79a3c313c167b4903466bfacd4da3bdb99420df988ab89cdd96a10",
            "2da2852ff7c134e5024100bafb0dac0fda53f9c755c23483343922727b88a5256a",
            "6fb47242e1c99b8f8a2c914f39f7af301219245786a6bb15336231d6a9b57ee7e0",
            "b3dd75129f93f54ecf"
        ))];

        assert_tokens(&signing_key.readable(), &tokens);
    }
}
