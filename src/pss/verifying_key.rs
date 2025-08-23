use super::{verify_digest, Signature};
use crate::RsaPublicKey;
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use signature::{hazmat::PrehashVerifier, DigestVerifier, Verifier};

#[cfg(feature = "encoding")]
use {
    crate::encoding::ID_RSASSA_PSS,
    const_oid::AssociatedOid,
    pkcs8::{Document, EncodePublicKey},
    spki::{der::AnyRef, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier},
};
#[cfg(feature = "serde")]
use {
    serdect::serde::{de, ser, Deserialize, Serialize},
    spki::DecodePublicKey,
};

/// Verifying key for checking the validity of RSASSA-PSS signatures as
/// described in [RFC8017 § 8.1].
///
/// [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
#[derive(Debug)]
pub struct VerifyingKey<D>
where
    D: Digest,
{
    pub(super) inner: RsaPublicKey,
    pub(super) salt_len: Option<usize>,
    pub(super) phantom: PhantomData<D>,
}

impl<D> VerifyingKey<D>
where
    D: Digest,
{
    /// Create a new RSASSA-PSS verifying key.
    /// Digest output size is used as a salt length.
    pub fn new(key: RsaPublicKey) -> Self {
        Self::new_with_salt_len(key, <D as Digest>::output_size())
    }

    /// Create a new RSASSA-PSS verifying key.
    pub fn new_with_salt_len(key: RsaPublicKey, salt_len: usize) -> Self {
        Self {
            inner: key,
            salt_len: Some(salt_len),
            phantom: Default::default(),
        }
    }

    /// Create a new RSASSA-PSS verifying key.
    /// Attempts to automatically detect the salt length.
    pub fn new_with_auto_salt_len(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            salt_len: None,
            phantom: Default::default(),
        }
    }

    /// Return specified salt length for this key
    pub fn salt_len(&self) -> Option<usize> {
        self.salt_len
    }
}

//
// `*Verifier` trait impls
//

impl<D> DigestVerifier<D, Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> signature::Result<()> {
        verify_digest::<D>(
            &self.inner,
            &digest.finalize(),
            &signature.inner,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

impl<D> PrehashVerifier<Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> signature::Result<()> {
        verify_digest::<D>(&self.inner, prehash, &signature.inner, self.salt_len)
            .map_err(|e| e.into())
    }
}

impl<D> Verifier<Signature> for VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> signature::Result<()> {
        verify_digest::<D>(
            &self.inner,
            &D::digest(msg),
            &signature.inner,
            self.salt_len,
        )
        .map_err(|e| e.into())
    }
}

//
// Other trait impls
//

impl<D> AsRef<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPublicKey {
        &self.inner
    }
}

#[cfg(feature = "encoding")]
impl<D> AssociatedAlgorithmIdentifier for VerifyingKey<D>
where
    D: Digest,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = pkcs1::ALGORITHM_ID;
}

// Implemented manually so we don't have to bind D with Clone
impl<D> Clone for VerifyingKey<D>
where
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            salt_len: self.salt_len,
            phantom: Default::default(),
        }
    }
}

#[cfg(feature = "encoding")]
impl<D> EncodePublicKey for VerifyingKey<D>
where
    D: Digest,
{
    fn to_public_key_der(&self) -> spki::Result<Document> {
        self.inner.to_public_key_der()
    }
}

impl<D> From<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: RsaPublicKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<VerifyingKey<D>> for RsaPublicKey
where
    D: Digest,
{
    fn from(key: VerifyingKey<D>) -> Self {
        key.inner
    }
}

#[cfg(feature = "encoding")]
impl<D> TryFrom<pkcs8::SubjectPublicKeyInfoRef<'_>> for VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    type Error = spki::Error;

    fn try_from(spki: pkcs8::SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        match spki.algorithm.oid {
            ID_RSASSA_PSS | pkcs1::ALGORITHM_OID => (),
            _ => {
                return Err(spki::Error::OidUnknown {
                    oid: spki.algorithm.oid,
                });
            }
        }

        RsaPublicKey::try_from(spki).map(Self::new)
    }
}

impl<D> PartialEq for VerifyingKey<D>
where
    D: Digest,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.salt_len == other.salt_len
    }
}

#[cfg(feature = "serde")]
impl<D> Serialize for VerifyingKey<D>
where
    D: Digest,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self.to_public_key_der().map_err(ser::Error::custom)?;
        serdect::slice::serialize_hex_lower_or_bin(&der, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, D> Deserialize<'de> for VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: serde::Deserializer<'de>,
    {
        let der_bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::from_public_key_der(&der_bytes).map_err(de::Error::custom)
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
        let pub_key = priv_key.to_public_key();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

        let tokens = [Token::Str(concat!(
            "30819f300d06092a864886f70d010101050003818d0030818902818100cd1419dc",
            "3771354bee0955a90489cce0c98aee6577851358afe386a68bc95287862a1157d5",
            "aba8847e8e57b6f2f94748ab7efda3f3c74a6702329397ffe0b1d4f76e1b025d87",
            "d583e48b3cfce99d6a507d94eb46c5242b3addb54d346ecf43eb0d7343bcb258a3",
            "1d5fa51f47b9e0d7280623901d1d29af1a986fec92ba5fe2430203010001",
        ))];

        assert_tokens(&verifying_key.readable(), &tokens);
    }
}
