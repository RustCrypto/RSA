use super::encrypt_digest;
use crate::{traits::RandomizedEncryptor, Result, RsaPublicKey};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use core::marker::PhantomData;
use digest::{Digest, FixedOutputReset};
use rand_core::CryptoRngCore;

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
    label: Option<String>,
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
    pub fn new_with_label<S: AsRef<str>>(key: RsaPublicKey, label: S) -> Self {
        Self {
            inner: key,
            label: Some(label.as_ref().to_string()),
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
    fn encrypt_with_rng<R: CryptoRngCore + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt_digest::<_, D, MGD>(rng, &self.inner, msg, self.label.as_ref().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "serde")]
    fn test_serde() {
        use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
        use sha2::Sha256;

        use crate::RsaPrivateKey;

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let encrypting_key = EncryptingKey::<Sha256>::new_with_label(
            RsaPrivateKey::new(&mut rng, 64).expect("failed to generate key").to_public_key(),
            "label",
        );

        let ser_encrypting_key =
            serde_json::to_string(&encrypting_key).expect("unable to serialize encrypting key");
        let deser_encrypting_key = serde_json::from_str::<EncryptingKey<Sha256>>(&ser_encrypting_key)
            .expect("unable to serialize encrypting key");

        assert_eq!(encrypting_key.label, deser_encrypting_key.label);
        assert_eq!(encrypting_key.inner, deser_encrypting_key.inner);
    }
}
