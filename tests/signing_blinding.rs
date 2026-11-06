//! Default signing must pass blinding randomness through every signing API.
#![cfg(feature = "encoding")]

use pkcs8::DecodePrivateKey;
use rand_core::{TryCryptoRng, TryRng};
use rsa::{Error, Pss, RsaPrivateKey, RsaPublicKey, pss, traits::SignatureScheme};
use sha2::{Digest, Sha256};
use signature::{
    RandomizedDigestSigner, RandomizedMultipartSigner, RandomizedSigner,
    hazmat::RandomizedPrehashSigner,
};

#[cfg(feature = "legacy-pkcs1v15")]
use rsa::{Pkcs1v15Sign, pkcs1v15};

// These are only tested with pkcs1v15
#[cfg(feature = "legacy-pkcs1v15")]
use signature::{DigestSigner, MultipartSigner, SignatureEncoding, Signer, hazmat::PrehashSigner};

fn key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_der(include_bytes!("examples/pkcs8/rsa2048-priv.der"))
        .expect("valid fixture")
}

#[derive(Debug)]
struct Exhausted;
impl core::fmt::Display for Exhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("test entropy budget exhausted")
    }
}
impl core::error::Error for Exhausted {}

// Supplies the PSS salt, then fails when base blinding requests more randomness.
struct SaltOnlyRng(usize);
impl TryRng for SaltOnlyRng {
    type Error = Exhausted;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        if bytes.len() > self.0 {
            return Err(Exhausted);
        }
        self.0 -= bytes.len();
        bytes.fill(0);
        Ok(())
    }
}
impl TryCryptoRng for SaltOnlyRng {}

#[test]
fn pss_default_requests_blinding_randomness() {
    let key = key();
    let digest = Sha256::digest(b"message");
    for salt_len in [0, 32] {
        let padding = Pss::<Sha256>::new_with_salt(salt_len);
        assert_eq!(
            padding.sign(Some(&mut SaltOnlyRng(salt_len)), &key, &digest),
            Err(Error::Rng)
        );

        // Control: the same salt, key and digest work when explicitly opting out of blinding.
        let mut padding = Pss::<Sha256>::new_with_salt(salt_len);
        padding.blinded = false;
        let signature = padding
            .sign(Some(&mut SaltOnlyRng(salt_len)), &key, &digest)
            .expect("unblinded control");
        key.to_public_key()
            .verify(Pss::<Sha256>::new_with_salt(salt_len), &digest, &signature)
            .expect("valid control signature");

        let signing = pss::SigningKey::<Sha256>::new_with_salt_len(key.clone(), salt_len);
        assert!(
            signing
                .try_sign_with_rng(&mut SaltOnlyRng(salt_len), b"message")
                .is_err()
        );
        assert!(
            signing
                .try_multipart_sign_with_rng(&mut SaltOnlyRng(salt_len), &[b"mes", b"sage"])
                .is_err()
        );
        assert!(
            signing
                .try_sign_digest_with_rng(&mut SaltOnlyRng(salt_len), |d| {
                    d.update(b"message");
                    Ok(())
                })
                .is_err()
        );
        assert!(
            signing
                .sign_prehash_with_rng(&mut SaltOnlyRng(salt_len), &digest)
                .is_err()
        );
    }
}

#[test]
fn default_rng_reaches_signature_scheme() {
    struct Probe;
    impl SignatureScheme for Probe {
        fn sign<R: TryCryptoRng + ?Sized>(
            self,
            rng: Option<&mut R>,
            _: &RsaPrivateKey,
            _: &[u8],
        ) -> rsa::Result<Vec<u8>> {
            assert_eq!(rng.is_some(), cfg!(feature = "getrandom"));
            Ok(Vec::new())
        }
        fn verify(self, _: &RsaPublicKey, _: &[u8], _: &[u8]) -> rsa::Result<()> {
            unreachable!()
        }
    }
    key().sign(Probe, b"").expect("default RNG dispatch");
}

#[test]
#[cfg(feature = "legacy-pkcs1v15")]
fn pkcs1v15_default_signatures_are_unchanged() {
    let key = key();
    let digest = Sha256::digest(b"message");
    let expected = Pkcs1v15Sign::new::<Sha256>()
        .sign::<SaltOnlyRng>(None, &key, &digest)
        .expect("unblinded reference");
    assert_eq!(
        key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .expect("generic sign"),
        expected
    );
    let signing = pkcs1v15::SigningKey::<Sha256>::new(key);
    assert_eq!(
        signing.try_sign(b"message").expect("sign").to_vec(),
        expected
    );
    assert_eq!(
        signing
            .try_multipart_sign(&[b"mes", b"sage"])
            .expect("multipart sign")
            .to_vec(),
        expected
    );
    assert_eq!(
        signing
            .sign_prehash(&digest)
            .expect("prehash sign")
            .to_vec(),
        expected
    );
    assert_eq!(
        signing
            .try_sign_digest(|d| {
                d.update(b"message");
                Ok(())
            })
            .expect("digest sign")
            .to_vec(),
        expected
    );
}
