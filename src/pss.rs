//! Support for the [Probabilistic Signature Scheme] (PSS) a.k.a. RSASSA-PSS.
//!
//! Designed by Mihir Bellare and Phillip Rogaway. Specified in [RFC8017 § 8.1].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pss-signatures).
//!
//! [Probabilistic Signature Scheme]: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
//! [RFC8017 § 8.1]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1

mod signature;
mod signing_key;
mod verifying_key;

pub use self::{signature::Signature, signing_key::SigningKey, verifying_key::VerifyingKey};

use alloc::vec::Vec;
use core::fmt::{self, Debug};

use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;

use crate::algorithms::pad::{i2osp, os2ip};
use crate::algorithms::pss::*;
use crate::algorithms::rsa::{rsa_decrypt_and_check, rsa_encrypt};
use crate::errors::{Error, Result};
use crate::traits::PublicKeyParts;
use crate::traits::SignatureScheme;
use crate::{PrivateKey, PublicKey};

#[cfg(feature = "getrandom")]
use crypto_common::getrandom::SysRng;

impl PublicKey {
    /// Verify a PSS signature after hashing `msg` with `D`.
    ///
    /// Requires a salt of `D`'s output size. For other salt lengths or automatic
    /// salt-length detection, use [`VerifyingKey`].
    ///
    /// # Errors
    /// Returns an error if the signature is invalid, including an incorrect salt length.
    pub fn pss_verify<D>(&self, msg: &[u8], sig: &[u8]) -> Result<()>
    where
        D: Digest + FixedOutputReset,
    {
        self.pss_verify_prehash::<D>(&D::digest(msg), sig)
    }

    /// Verify a PSS signature over a message hash computed using `D`.
    ///
    /// The hash is verified directly, without hashing it again. Requires a salt of
    /// `D`'s output size. For other salt lengths or automatic salt-length detection,
    /// use [`VerifyingKey`].
    ///
    /// # Errors
    /// Returns an error if the hash has the wrong length or the signature is invalid,
    /// including an incorrect salt length.
    pub fn pss_verify_prehash<D>(&self, hash: &[u8], sig: &[u8]) -> Result<()>
    where
        D: Digest + FixedOutputReset,
    {
        verify_digest::<D>(self, hash, sig, Some(<D as Digest>::output_size()))
    }
}

impl PrivateKey {
    /// Sign `msg` using PSS after hashing it with `D`.
    ///
    /// Uses the operating system RNG for the salt and blinding. The salt length is
    /// `D`'s output size. For other salt lengths, use [`SigningKey`].
    ///
    /// # Errors
    /// Returns an error if the key is too small for `D` or the private operation fails,
    /// including RNG failures.
    #[cfg(feature = "getrandom")]
    pub fn pss_sign<D>(&self, msg: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        self.pss_sign_with_rng::<D, _>(&mut SysRng, msg)
    }

    /// Sign a message hash computed using `D` with PSS, without hashing it again.
    ///
    /// Uses the operating system RNG for the salt and blinding. The salt length is
    /// `D`'s output size. For other salt lengths, use [`SigningKey`].
    ///
    /// # Errors
    /// Returns [`Error::InputNotHashed`] if `hash` has the wrong length, or an error
    /// if the key is too small for `D` or the private operation fails, including RNG failures.
    #[cfg(feature = "getrandom")]
    pub fn pss_sign_prehash<D>(&self, hash: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
    {
        self.pss_sign_prehash_with_rng::<D, _>(&mut SysRng, hash)
    }

    /// Sign `msg` using PSS after hashing it with `D`.
    ///
    /// Uses the provided RNG for the salt and blinding. The salt length is `D`'s
    /// output size. For other salt lengths, use [`SigningKey`].
    ///
    /// # Errors
    /// Returns an error if the key is too small for `D` or the private operation fails,
    /// including RNG failures.
    pub fn pss_sign_with_rng<D, R>(&self, rng: &mut R, msg: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
        R: TryCryptoRng + ?Sized,
    {
        self.pss_sign_prehash_with_rng::<D, _>(rng, &D::digest(msg))
    }

    /// Sign a message hash computed using `D` with PSS, without hashing it again.
    ///
    /// Uses the provided RNG for the salt and blinding. The salt length is `D`'s
    /// output size. For other salt lengths, use [`SigningKey`].
    ///
    /// # Errors
    /// Returns [`Error::InputNotHashed`] if `hash` has the wrong length, or an error
    /// if the key is too small for `D` or the private operation fails, including RNG failures.
    pub fn pss_sign_prehash_with_rng<D, R>(&self, rng: &mut R, hash: &[u8]) -> Result<Vec<u8>>
    where
        D: Digest + FixedOutputReset,
        R: TryCryptoRng + ?Sized,
    {
        if hash.len() != <D as Digest>::output_size() {
            return Err(Error::InputNotHashed);
        }

        sign_digest::<_, D>(rng, true, self, hash, <D as Digest>::output_size())
    }
}

/// DEPRECATED: type alias for legacy blinded signing key. Blinding is now applied automatically
/// when available.
#[deprecated(
    since = "0.10.0",
    note = "use `SigningKey` which is blinded automatically"
)]
pub type BlindedSigningKey<D> = SigningKey<D>;

#[cfg(feature = "encoding")]
use {
    crate::encoding::ID_RSASSA_PSS,
    const_oid::AssociatedOid,
    pkcs1::RsaPssParams,
    spki::{
        AlgorithmIdentifierOwned,
        der::{Any, ErrorKind},
    },
};

/// Digital signatures using PSS padding.
pub struct Pss<D> {
    /// Enable RSA base blinding for the private operation (enabled by default).
    /// This does not change the RSASSA-PSS signature format.
    pub blinded: bool,

    /// Digest type to use.
    pub digest: D,

    /// Salt length.
    /// Required for signing, optional for verifying.
    pub salt_len: Option<usize>,
}

impl<D> Default for Pss<D>
where
    D: Digest,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D> Pss<D>
where
    D: Digest,
{
    /// New PSS padding for the given digest.
    /// Digest output size is used as a salt length.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_salt(<D as Digest>::output_size())
    }

    /// New PSS padding for the given digest with a salt value of the given length.
    #[must_use]
    pub fn new_with_salt(len: usize) -> Self {
        Self {
            blinded: true,
            digest: D::new(),
            salt_len: Some(len),
        }
    }

    /// New PSS padding with RSA base blinding for the given digest.
    /// Digest output size is used as a salt length.
    #[must_use]
    pub fn new_blinded() -> Self {
        Self::new_blinded_with_salt(<D as Digest>::output_size())
    }

    /// New PSS padding with RSA base blinding for the given digest
    /// with a salt value of the given length.
    #[must_use]
    pub fn new_blinded_with_salt(len: usize) -> Self {
        Self {
            blinded: true,
            digest: D::new(),
            salt_len: Some(len),
        }
    }
}

impl<D> SignatureScheme for Pss<D>
where
    D: Digest + FixedOutputReset,
{
    #[allow(clippy::unwrap_in_result, reason = "TODO")]
    fn sign<Rng: TryCryptoRng + ?Sized>(
        mut self,
        rng: Option<&mut Rng>,
        priv_key: &PrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>> {
        sign(
            rng.ok_or(Error::InvalidPaddingScheme)?,
            self.blinded,
            priv_key,
            hashed,
            self.salt_len.expect("salt_len to be Some"),
            &mut self.digest,
        )
    }

    fn verify(mut self, pub_key: &PublicKey, hashed: &[u8], sig: &[u8]) -> Result<()> {
        verify(pub_key, hashed, sig, &mut self.digest, self.salt_len)
    }
}

impl<D> Debug for Pss<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PSS")
            .field("blinded", &self.blinded)
            .field("digest", &"...")
            .field("salt_len", &self.salt_len)
            .finish()
    }
}

pub(crate) fn verify<D>(
    pub_key: &PublicKey,
    hashed: &[u8],
    sig: &[u8],
    digest: &mut D,
    salt_len: Option<usize>,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let mut em = decode_signature(pub_key, sig)?;
    let em_bits = pub_key.n().bit_width() as usize - 1;
    emsa_pss_verify(hashed, &mut em, salt_len, digest, em_bits)
}

pub(crate) fn verify_digest<D>(
    pub_key: &PublicKey,
    hashed: &[u8],
    sig: &[u8],
    salt_len: Option<usize>,
) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let mut em = decode_signature(pub_key, sig)?;
    let em_bits = pub_key.n().bit_width() as usize - 1;
    emsa_pss_verify_digest::<D>(hashed, &mut em, salt_len, em_bits)
}

/// Performs the length, RSAVP1, and I2OSP steps of RFC8017 §8.1.2.
fn decode_signature(pub_key: &PublicKey, signature: &[u8]) -> Result<Vec<u8>> {
    // Step 1: `S` must be exactly `k` octets, independently of integer storage precision.
    if signature.len() != pub_key.size() {
        return Err(Error::Verification);
    }

    // Steps 2a and 2b: `s = OS2IP(S), m = RSAVP1((n, e), s)`.
    let s = os2ip(signature, pub_key.n_bits_precision()).map_err(|_| Error::Verification)?;
    if s >= *pub_key.n().as_ref() {
        return Err(Error::Verification);
    }
    let m = rsa_encrypt(pub_key, &s)?;

    // Step 2c: EM has `emLen` octets, which can be `k - 1`.
    //
    // Check the public representative's width before calling infallible I2OSP; discarding a nonzero
    // leading octet is invalid.
    let em_bits = pub_key.n().bit_width() as usize - 1;
    let em_len = em_bits.div_ceil(8);
    if m.bit_width() as usize > 8 * em_len {
        return Err(Error::Verification);
    }
    Ok(i2osp(m, em_len))
}

/// SignPSS calculates the signature of hashed using RSASSA-PSS.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. The opts argument may be nil, in which case sensible
/// defaults are used.
pub(crate) fn sign<T, D>(
    rng: &mut T,
    blind: bool,
    priv_key: &PrivateKey,
    hashed: &[u8],
    salt_len: usize,
    digest: &mut D,
) -> Result<Vec<u8>>
where
    T: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
{
    let mut salt = vec![0; salt_len];
    rng.try_fill_bytes(&mut salt[..]).map_err(|_| Error::Rng)?;

    sign_pss_with_salt(blind.then_some(rng), priv_key, hashed, &salt, digest)
}

pub(crate) fn sign_digest<T, D>(
    rng: &mut T,
    blind: bool,
    priv_key: &PrivateKey,
    hashed: &[u8],
    salt_len: usize,
) -> Result<Vec<u8>>
where
    T: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
{
    let mut salt = vec![0; salt_len];
    rng.try_fill_bytes(&mut salt[..]).map_err(|_| Error::Rng)?;

    sign_pss_with_salt_digest::<_, D>(blind.then_some(rng), priv_key, hashed, &salt)
}

/// signPSSWithSalt calculates the signature of hashed using PSS with specified salt.
///
/// Note that hashed must be the result of hashing the input message using the
/// given hash function. salt is a random sequence of bytes whose length will be
/// later used to verify the signature.
fn sign_pss_with_salt<T, D>(
    blind_rng: Option<&mut T>,
    priv_key: &PrivateKey,
    hashed: &[u8],
    salt: &[u8],
    digest: &mut D,
) -> Result<Vec<u8>>
where
    T: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
{
    let em_bits = priv_key.n().bit_width() - 1;

    let em = emsa_pss_encode(hashed, em_bits as _, salt, digest)?;

    let em = os2ip(&em, priv_key.n_bits_precision())?;
    let raw = rsa_decrypt_and_check(priv_key, blind_rng, &em)?;
    Ok(i2osp(raw, priv_key.size()))
}

fn sign_pss_with_salt_digest<T, D>(
    blind_rng: Option<&mut T>,
    priv_key: &PrivateKey,
    hashed: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>>
where
    T: TryCryptoRng + ?Sized,
    D: Digest + FixedOutputReset,
{
    let em_bits = priv_key.n().bit_width() - 1;
    let em = emsa_pss_encode_digest::<D>(hashed, em_bits as _, salt)?;

    let em = os2ip(&em, priv_key.n_bits_precision())?;
    Ok(i2osp(
        rsa_decrypt_and_check(priv_key, blind_rng, &em)?,
        priv_key.size(),
    ))
}

/// Returns the [`AlgorithmIdentifierOwned`] associated with PSS signature using a given digest.
#[cfg(feature = "encoding")]
#[allow(clippy::missing_errors_doc, reason = "TODO")]
pub fn get_default_pss_signature_algo_id<D>() -> spki::Result<AlgorithmIdentifierOwned>
where
    D: Digest + AssociatedOid,
{
    get_pss_signature_algo_id::<D>(<D as Digest>::output_size())
}

#[cfg(feature = "encoding")]
fn get_pss_signature_algo_id<D>(salt_len: usize) -> spki::Result<AlgorithmIdentifierOwned>
where
    D: Digest + AssociatedOid,
{
    // RsaPssParams encodes salt_len in a single byte; reject rather than truncate.
    let salt_len = u8::try_from(salt_len).map_err(|_| ErrorKind::Overflow.to_error())?;
    let pss_params = RsaPssParams::new::<D>(salt_len);

    Ok(AlgorithmIdentifierOwned {
        oid: ID_RSASSA_PSS,
        parameters: Some(Any::encode_from(&pss_params)?),
    })
}

#[cfg(all(test, feature = "encoding"))]
mod test {
    use crate::pss::{Pss, Signature, SigningKey, VerifyingKey};
    use crate::{PrivateKey, PublicKey};

    use crate::traits::PublicKeyParts;
    use hex_literal::hex;
    use pkcs1::DecodeRsaPrivateKey;
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;
    use rstest::rstest;
    use sha1::{Digest, Sha1};
    use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
    use signature::{DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner, Verifier};

    use super::get_default_pss_signature_algo_id;
    use spki::DynSignatureAlgorithmIdentifier;

    fn get_private_key() -> PrivateKey {
        // In order to generate new test vectors you'll need the PEM form of this key:
        // -----BEGIN RSA PRIVATE KEY-----
        // MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
        // fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
        // /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
        // RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
        // EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
        // IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
        // tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
        // -----END RSA PRIVATE KEY-----

        let pem = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA PRIVATE KEY-----"#;

        PrivateKey::from_pkcs1_pem(pem).unwrap()
    }

    #[rstest]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
        ),
        true,
    )]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
        ),
        false,
    )]
    fn test_verify_pss(#[case] text: &str, #[case] sig: [u8; 64], #[case] expected: bool) {
        let priv_key = get_private_key();
        let pub_key: PublicKey = priv_key.into();

        let digest = Sha1::digest(text.as_bytes()).to_vec();
        let result = pub_key.verify(Pss::<Sha1>::new(), &digest, &sig);

        match expected {
            true => result.expect("failed to verify"),
            false => {
                result.expect_err("expected verifying error");
            }
        }
    }

    #[rstest]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
        ),
        true,
    )]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
        ),
        false,
    )]
    fn test_verify_pss_signer(#[case] text: &str, #[case] sig: [u8; 64], #[case] expected: bool) {
        let priv_key = get_private_key();
        let pub_key: PublicKey = priv_key.into();
        let verifying_key: VerifyingKey<Sha1> = VerifyingKey::new(pub_key);

        let result = verifying_key.verify(
            text.as_bytes(),
            &Signature::try_from(sig.as_slice()).unwrap(),
        );
        match expected {
            true => result.expect("failed to verify"),
            false => {
                result.expect_err("expected verifying error");
            }
        }
    }

    #[rstest]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
        ),
        true,
    )]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
        ),
        false,
    )]
    fn test_verify_pss_digest_signer(
        #[case] text: &str,
        #[case] sig: [u8; 64],
        #[case] expected: bool,
    ) {
        let priv_key = get_private_key();
        let pub_key: PublicKey = priv_key.into();
        let verifying_key = VerifyingKey::new(pub_key);

        let result = verifying_key.verify_digest(
            |digest: &mut Sha1| {
                digest.update(text.as_bytes());
                Ok(())
            },
            &Signature::try_from(sig.as_slice()).unwrap(),
        );
        match expected {
            true => result.expect("failed to verify"),
            false => {
                result.expect_err("expected verifying error");
            }
        }
    }

    #[rstest]
    #[case("test\n")]
    fn test_sign_and_verify_roundtrip(#[case] test: &str) {
        let priv_key = get_private_key();

        let mut rng = ChaCha8Rng::from_seed([42; 32]);

        let digest = Sha1::digest(test.as_bytes()).to_vec();
        let sig = priv_key
            .sign_with_rng(&mut rng, Pss::<Sha1>::new(), &digest)
            .expect("failed to sign");

        priv_key
            .to_public_key()
            .verify(Pss::<Sha1>::new(), &digest, &sig)
            .expect("failed to verify");
    }

    #[rstest]
    #[case("test\n")]
    fn test_sign_blinded_and_verify_roundtrip(#[case] test: &str) {
        let priv_key = get_private_key();

        let mut rng = ChaCha8Rng::from_seed([42; 32]);

        let digest = Sha1::digest(test.as_bytes()).to_vec();
        let sig = priv_key
            .sign_with_rng(&mut rng, Pss::<Sha1>::new_blinded(), &digest)
            .expect("failed to sign");

        priv_key
            .to_public_key()
            .verify(Pss::<Sha1>::new(), &digest, &sig)
            .expect("failed to verify");
    }

    #[rstest]
    #[case("test\n")]
    fn test_sign_and_verify_roundtrip_signer(#[case] test: &str) {
        let priv_key = get_private_key();

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        let sig = signing_key.sign_with_rng(&mut rng, test.as_bytes());
        verifying_key
            .verify(test.as_bytes(), &sig)
            .expect("failed to verify");
    }

    #[rstest]
    #[case("test\n")]
    fn test_sign_and_verify_roundtrip_digest_signer(#[case] test: &str) {
        let priv_key = get_private_key();

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        let sig = signing_key
            .sign_digest_with_rng(&mut rng, |digest: &mut Sha1| digest.update(test.as_bytes()));

        verifying_key
            .verify_digest(
                |digest: &mut Sha1| {
                    digest.update(test.as_bytes());
                    Ok(())
                },
                &sig,
            )
            .expect("failed to verify");
    }

    #[rstest]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962f"
        ),
        true
    )]
    #[case(
        "test\n",
        hex!(
            "6f86f26b14372b2279f79fb6807c49889835c204f71e38249b4c5601462da8ae"
            "30f26ffdd9c13f1c75eee172bebe7b7c89f2f1526c722833b9737d6c172a962e"
        ),
        false
    )]
    fn test_verify_pss_hazmat(#[case] text: &str, #[case] sig: [u8; 64], #[case] expected: bool) {
        let text = Sha1::digest(text);
        let priv_key = get_private_key();

        let pub_key: PublicKey = priv_key.into();
        let verifying_key = VerifyingKey::<Sha1>::new(pub_key);

        let result = verifying_key
            .verify_prehash(text.as_ref(), &Signature::try_from(sig.as_slice()).unwrap());
        match expected {
            true => result.expect("failed to verify"),
            false => {
                result.expect_err("expected verifying error");
            }
        }
    }

    #[rstest]
    #[case("test\n")]
    fn test_sign_and_verify_pss_hazmat(#[case] test: &str) {
        let test = &Sha1::digest(test);
        let priv_key = get_private_key();

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let verifying_key = signing_key.verifying_key();

        let sig = signing_key
            .sign_prehash_with_rng(&mut rng, test)
            .expect("failed to sign");
        verifying_key
            .verify_prehash(test, &sig)
            .expect("failed to verify");
    }

    #[test]
    // Tests the corner case where the key is multiple of 8 + 1 bits long
    fn test_sign_and_verify_2049bit_key() {
        let plaintext = "Hello\n";
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        for _ in 0..10 {
            let priv_key = PrivateKey::new(&mut rng, 2049).unwrap();

            let digest = Sha1::digest(plaintext.as_bytes()).to_vec();
            let sig = priv_key
                .sign_with_rng(&mut rng, Pss::<Sha1>::new(), &digest)
                .expect("failed to sign");

            priv_key
                .to_public_key()
                .verify(Pss::<Sha1>::new(), &digest, &sig)
                .expect("failed to verify");
        }
    }

    // Tests the case where the salt length used for signing differs from the default length
    // while the verifier uses auto-detection.
    #[rstest]
    #[case("test\n")]
    fn test_sign_and_verify_pss_differing_salt_len(#[case] test: &str) {
        let priv_key = get_private_key();

        let mut rng = ChaCha8Rng::from_seed([42; 32]);

        // signing keys using different salt lengths
        let signing_keys = [
            // default salt length
            SigningKey::<Sha1>::new(priv_key.clone()),
            // maximum salt length
            SigningKey::<Sha1>::new_with_salt_len(
                priv_key.clone(),
                priv_key.size() - Sha1::output_size() - 2,
            ),
            // unsalted
            SigningKey::<Sha1>::new_with_salt_len(priv_key.clone(), 0),
        ];

        // verifying key uses default salt length strategy
        let verifying_key = VerifyingKey::<Sha1>::new_with_auto_salt_len(priv_key.to_public_key());

        for signing_key in &signing_keys {
            let sig = signing_key.sign_with_rng(&mut rng, test.as_bytes());
            verifying_key
                .verify(test.as_bytes(), &sig)
                .expect("verification to succeed");
        }
    }

    // A salt length that does not fit in a byte must be rejected, not truncated (#703).
    #[test]
    fn signature_algorithm_identifier_rejects_oversized_salt_len() {
        use spki::DynSignatureAlgorithmIdentifier;

        let priv_key = get_private_key();

        // largest value that fits in a byte
        let ok_key = SigningKey::<Sha1>::new_with_salt_len(priv_key.clone(), 255);
        assert!(ok_key.signature_algorithm_identifier().is_ok());

        // would wrap to 0
        let bad_key = SigningKey::<Sha1>::new_with_salt_len(priv_key.clone(), 256);
        assert!(bad_key.signature_algorithm_identifier().is_err());
    }

    /// `signature_algorithm_identifier()` must advertise the configured salt length
    /// verbatim: the encoded `AlgorithmIdentifier` parameters must DER-round-trip
    /// back to the same `salt_len` for both signing key types (see issue #703).
    #[rstest]
    #[case(255)]
    #[case(128)]
    fn test_pss_algo_id_salt_len_representable(#[case] salt_len: usize) {
        use spki::der::Encode;

        let priv_key = get_private_key();

        let signing_key = SigningKey::<Sha1>::new_with_salt_len(priv_key.clone(), salt_len);

        let algo_id = signing_key
            .signature_algorithm_identifier()
            .expect("salt_len fits in a u8, so encoding must succeed");

        let params_bytes = algo_id
            .parameters
            .as_ref()
            .expect("RSA-PSS AlgorithmIdentifier carries parameters")
            .to_der()
            .expect("parameters are DER-encodable");
        let pss_params = <pkcs1::RsaPssParamsOwned as spki::der::Decode>::from_der(&params_bytes)
            .expect("RSA-PSS parameters are DER-decodable");
        assert_eq!(pss_params.salt_len as usize, salt_len);
    }

    #[rstest]
    #[case(256)]
    #[case(300)]
    #[case(usize::MAX)]
    fn test_pss_algo_id_salt_len_out_of_range(#[case] salt_len: usize) {
        let priv_key = get_private_key();
        let signing_key = SigningKey::<Sha1>::new_with_salt_len(priv_key.clone(), salt_len);

        signing_key
            .signature_algorithm_identifier()
            .expect_err("salt_len overflows the u8 in RsaPssParams, so encoding must fail");
    }

    /// The digest-size default salt length is unchanged by the `u8` validation.
    #[test]
    fn test_pss_algo_id_default_salt_len_unchanged() {
        use spki::der::Encode;

        let algo_id = get_default_pss_signature_algo_id::<Sha1>()
            .expect("the default salt length must remain encodable");
        let params_bytes = algo_id
            .parameters
            .as_ref()
            .expect("RSA-PSS AlgorithmIdentifier carries parameters")
            .to_der()
            .expect("parameters are DER-encodable");
        let pss_params = <pkcs1::RsaPssParamsOwned as spki::der::Decode>::from_der(&params_bytes)
            .expect("RSA-PSS parameters are DER-decodable");
        assert_eq!(pss_params.salt_len as usize, Sha1::output_size());
    }
}
