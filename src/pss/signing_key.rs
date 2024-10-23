use super::{get_pss_signature_algo_id, sign_digest, Signature, VerifyingKey};
use crate::encoding::verify_algorithm_id;
use crate::{Result, RsaPrivateKey};
use const_oid::AssociatedOid;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use pkcs8::{
    spki::{
        der::AnyRef, AlgorithmIdentifierOwned, AlgorithmIdentifierRef,
        AssociatedAlgorithmIdentifier, DynSignatureAlgorithmIdentifier,
    },
    EncodePrivateKey, SecretDocument,
};
use rand_core::CryptoRngCore;
use signature::{
    hazmat::RandomizedPrehashSigner, Keypair, RandomizedDigestSigner, RandomizedSigner,
};
use zeroize::ZeroizeOnDrop;
#[cfg(feature = "serde")]
use {
    pkcs8::DecodePrivateKey,
    serdect::serde::{de, ser, Deserialize, Serialize},
};

#[cfg(feature = "getrandom")]
use {
    rand_core::OsRng,
    signature::{hazmat::PrehashSigner, Signer},
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
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::random_with_salt_len(rng, bit_size, <D as Digest>::output_size())
    }

    /// Generate a new random RSASSA-PSS signing key with a salt of the given length.
    pub fn random_with_salt_len<R: CryptoRngCore + ?Sized>(
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
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
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
    fn try_sign_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_sign_digest_with_rng(rng, D::new_with_prefix(msg))
    }
}

impl<D> RandomizedPrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash_with_rng(
        &self,
        rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> signature::Result<Signature> {
        sign_digest::<_, D>(rng, false, &self.inner, prehash, self.salt_len)?
            .as_slice()
            .try_into()
    }
}

#[cfg(feature = "getrandom")]
impl<D> PrehashSigner<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        self.sign_prehash_with_rng(&mut OsRng, prehash)
    }
}

#[cfg(feature = "getrandom")]
impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        self.try_sign_with_rng(&mut OsRng, msg)
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

impl<D> AssociatedAlgorithmIdentifier for SigningKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

impl<D> DynSignatureAlgorithmIdentifier for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn signature_algorithm_identifier(&self) -> pkcs8::spki::Result<AlgorithmIdentifierOwned> {
        get_pss_signature_algo_id::<D>(self.salt_len as u8)
    }
}

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
        let priv_key = crate::RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key");
        let signing_key = SigningKey::<Sha256>::new(priv_key);

        let tokens = [
            Token::Str("3054020100300d06092a864886f70d01010105000440303e020100020900cc6c6130e35b46bf0203010001020863de1ac858580019020500f65cff5d020500d46b68cb02046d9a09f102047b4e3a4f020500f45065cc")
        ];

        assert_tokens(&signing_key.readable(), &tokens);
    }
}
