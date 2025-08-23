//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

mod decrypting_key;
mod encrypting_key;
mod signature;
mod signing_key;
mod verifying_key;

pub use self::{
    decrypting_key::DecryptingKey, encrypting_key::EncryptingKey, signature::Signature,
    signing_key::SigningKey, verifying_key::VerifyingKey,
};

use alloc::{boxed::Box, vec::Vec};
use const_oid::AssociatedOid;
use core::fmt::Debug;
use crypto_bigint::BoxedUint;
use digest::Digest;
use rand_core::TryCryptoRng;

use crate::algorithms::pad::{uint_to_be_pad, uint_to_zeroizing_be_pad};
use crate::algorithms::pkcs1v15::*;
use crate::algorithms::rsa::{rsa_decrypt_and_check, rsa_encrypt};
use crate::errors::{Error, Result};
use crate::key::{self, RsaPrivateKey, RsaPublicKey};
use crate::traits::{PaddingScheme, PublicKeyParts, SignatureScheme};

/// Encryption using PKCS#1 v1.5 padding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pkcs1v15Encrypt;

impl PaddingScheme for Pkcs1v15Encrypt {
    fn decrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        decrypt(rng, priv_key, ciphertext)
    }

    fn encrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt(rng, pub_key, msg)
    }
}

/// `RSASSA-PKCS1-v1_5`: digital signatures using PKCS#1 v1.5 padding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs1v15Sign {
    /// Length of hash to use.
    pub hash_len: Option<usize>,

    /// Prefix.
    pub prefix: Box<[u8]>,
}

impl Pkcs1v15Sign {
    /// Create new PKCS#1 v1.5 padding for the given digest.
    ///
    /// The digest must have an [`AssociatedOid`]. Make sure to enable the `oid`
    /// feature of the relevant digest crate.
    pub fn new<D>() -> Self
    where
        D: Digest + AssociatedOid,
    {
        Self {
            hash_len: Some(<D as Digest>::output_size()),
            prefix: pkcs1v15_generate_prefix::<D>().into_boxed_slice(),
        }
    }

    /// Create new PKCS#1 v1.5 padding for computing an unprefixed signature.
    ///
    /// This sets `hash_len` to `None` and uses an empty `prefix`.
    pub fn new_unprefixed() -> Self {
        Self {
            hash_len: None,
            prefix: Box::new([]),
        }
    }
}

impl SignatureScheme for Pkcs1v15Sign {
    fn sign<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(hash_len) = self.hash_len {
            if hashed.len() != hash_len {
                return Err(Error::InputNotHashed);
            }
        }

        sign(rng, priv_key, &self.prefix, hashed)
    }

    fn verify(self, pub_key: &RsaPublicKey, hashed: &[u8], sig: &[u8]) -> Result<()> {
        if let Some(hash_len) = self.hash_len {
            if hashed.len() != hash_len {
                return Err(Error::InputNotHashed);
            }
        }

        verify(
            pub_key,
            self.prefix.as_ref(),
            hashed,
            &BoxedUint::from_be_slice_vartime(sig),
        )
    }
}

/// Encrypts the given message with RSA and the padding
/// scheme from PKCS#1 v1.5.  The message must be no longer than the
/// length of the public modulus minus 11 bytes.
#[inline]
fn encrypt<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    pub_key: &RsaPublicKey,
    msg: &[u8],
) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let em = pkcs1v15_encrypt_pad(rng, msg, pub_key.size())?;
    let int = BoxedUint::from_be_slice(&em, pub_key.n_bits_precision())?;
    uint_to_be_pad(rsa_encrypt(pub_key, &int)?, pub_key.size())
}

/// Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5.
///
/// If an `rng` is passed, it uses RSA blinding to avoid timing side-channel attacks.
///
/// Note that whether this function returns an error or not discloses secret
/// information. If an attacker can cause this function to run repeatedly and
/// learn whether each instance returned an error then they can decrypt and
/// forge signatures as if they had the private key. See
/// `decrypt_session_key` for a way of solving this problem.
#[inline]
fn decrypt<R: TryCryptoRng + ?Sized>(
    rng: Option<&mut R>,
    priv_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    key::check_public(priv_key)?;

    let ciphertext = BoxedUint::from_be_slice(ciphertext, priv_key.n_bits_precision())?;
    let em = rsa_decrypt_and_check(priv_key, rng, &ciphertext)?;
    let em = uint_to_zeroizing_be_pad(em, priv_key.size())?;

    pkcs1v15_encrypt_unpad(em, priv_key.size())
}

/// Calculates the signature of hashed using
/// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5. Note that `hashed` must
/// be the result of hashing the input message using the given hash
/// function. If hash is `None`, hashed is signed directly. This isn't
/// advisable except for interoperability.
///
/// If `rng` is not `None` then RSA blinding will be used to avoid timing
/// side-channel attacks.
///
/// This function is deterministic. Thus, if the set of possible
/// messages is small, an attacker may be able to build a map from
/// messages to signatures and identify the signed messages. As ever,
/// signatures provide authenticity, not confidentiality.
#[inline]
fn sign<R: TryCryptoRng + ?Sized>(
    rng: Option<&mut R>,
    priv_key: &RsaPrivateKey,
    prefix: &[u8],
    hashed: &[u8],
) -> Result<Vec<u8>> {
    let em = pkcs1v15_sign_pad(prefix, hashed, priv_key.size())?;

    let em = BoxedUint::from_be_slice(&em, priv_key.n_bits_precision())?;
    uint_to_zeroizing_be_pad(rsa_decrypt_and_check(priv_key, rng, &em)?, priv_key.size())
}

/// Verifies an RSA PKCS#1 v1.5 signature.
#[inline]
fn verify(pub_key: &RsaPublicKey, prefix: &[u8], hashed: &[u8], sig: &BoxedUint) -> Result<()> {
    let n = pub_key.n();
    if sig >= n.as_ref() || sig.bits_precision() != pub_key.n_bits_precision() {
        return Err(Error::Verification);
    }

    let em = uint_to_be_pad(rsa_encrypt(pub_key, sig)?, pub_key.size())?;

    pkcs1v15_sign_unpad(prefix, hashed, &em, pub_key.size())
}

mod oid {
    use const_oid::ObjectIdentifier;

    /// A trait which associates an RSA-specific OID with a type.
    pub trait RsaSignatureAssociatedOid {
        /// The OID associated with this type.
        const OID: ObjectIdentifier;
    }

    #[cfg(feature = "sha1")]
    impl RsaSignatureAssociatedOid for sha1::Sha1 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha224 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha256 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha384 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
    }

    #[cfg(feature = "sha2")]
    impl RsaSignatureAssociatedOid for sha2::Sha512 {
        const OID: ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    }
}

pub use oid::RsaSignatureAssociatedOid;

#[cfg(test)]
mod tests {
    use super::*;
    use ::signature::{
        hazmat::{PrehashSigner, PrehashVerifier},
        DigestSigner, DigestVerifier, Keypair, RandomizedDigestSigner, RandomizedSigner,
        SignatureEncoding, Signer, Verifier,
    };
    use base64ct::{Base64, Encoding};
    use hex_literal::hex;
    use rand_chacha::{
        rand_core::{RngCore, SeedableRng},
        ChaCha8Rng,
    };
    use sha1::{Digest, Sha1};
    use sha2::Sha256;
    use sha3::Sha3_256;

    use crate::traits::{
        Decryptor, EncryptingKeypair, PublicKeyParts, RandomizedDecryptor, RandomizedEncryptor,
    };
    use crate::{RsaPrivateKey, RsaPublicKey};

    fn get_private_key() -> RsaPrivateKey {
        // https://github.com/C2SP/wycheproof/blob/main/testvectors/rsa_oaep_misc_test.json
        RsaPrivateKey::from_components(
            BoxedUint::from_be_hex("d0941e63a980fa92fb25ed4c7b3307f827023034ae7f1a7491f0699ca7607285e62ad8e994bac21b8b6e305e334f4874067d28e304230dca7f0e85f7ce595770b6e054c9f844ba86c0696eeba0769d8d4a347e8fe85c724ac1c44994af18a39e719f721f1bc50c46a39e6c075fcd1649f01f22608ce7dc6955502258336987d9", 1024).unwrap(),
            BoxedUint::from(65_537u64),
            BoxedUint::from_be_hex("5ff4a47e690ea338573e3d8b3fea5c32378ff4296855a51017cba86a9f3de9b1dc0fbe36c76b9bbd1c4a170a5f448c2a8489b3f3ac858be4aacb3daaa14dccc183622eedd3ae6f0427a2a298b51b97818a5430f13705f42d8b25476f939c935e389e30d9ade5d0180920135f5aef0c5fecd15f00b83b51dab8ba930d88826801", 1024).unwrap(),
            vec![
                BoxedUint::from_be_hex("e882d12d5f0be26a80359f13c08210bdcbf759dfee695313efa8886919659b064e3c656a267af6275ed1af89a5dfe9e25b31a02bafbd59445b7507a22989a681", 512).unwrap(),
                BoxedUint::from_be_hex("e5a65cfa668bd857d59135a78c18c8adb7c222368e9d74abad8e83299f7ac3c2ad7aa44ddb05deea6d9b20dbaf09a8615284a17c72d3723240334685ea7e2559", 512).unwrap(),
            ],
        ).unwrap()
    }

    #[test]
    fn test_decrypt_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [
            [
                "f0f4qsNunKxRgsag5/p3AER7uoqs/Gupe33kuJWGAkLjobLsLszxp7uwVngeoxpDi87rTcJ9y0Sbu2QfnV/KvwEHiuQ8NL1FCRt4ujwgNtQms9XHjkTeLUX9tapoxdA0QhLsjblZFdb3fAvZXHGKPTBdHkxHut6LHG37SxbHeQY=",
                "x",
            ],
            [
                "l+L4+CdrgcFJ9LngppA+o7pZAKmZs4Gu5cRsum7OAji0+XNamTaPKxgtAio5A8ltRLJxrfZnRFOIOyn4964vMIB2YfVG/Vak//kLIn/rbgaVGndmWxQuR6ykEruOuqn5JUqv4JHaW30aDzEkCbpXWpFJ7dhfrWZdSv4XKpt9cY4=",
                "testing.",
            ],
            [
                "JtlpY3lTeCmkRRrIgfuOXH0ubMOL1U/n6nM6r6kF2iuRiFIPapfEzHF2WSvrbxZXa8gzJo1PuAJiJ6Vy90vOWbP43VEXLk5wyGZPePwHQ1WwOcE+6okZ9j9zmAmAnQUyaUjPfhwyDC64ObjiSKeIPCYSsdURy/Z67lcTZ6JJ8+8=",
                "testing.\n",
            ],
            [
                "TcyqI5jrGyln5AspqnvWShPIjKIZtXbNApf9TqAZrsl31RS+k6blEJy6YVZeow9QKis+UyIcz08nMGX/D3lm/JA4bwpyBFAvSFr2MNjNpGh9QqEcGryI0CpLA1fy56x7YGB/Y0eJZXnSj91udGubJTEI9ULTouoFAKxoWq7ioTc=",
                "01234567890123456789012345678901234567890123456789012",
            ],
        ];

        for test in &tests {
            let out = priv_key
                .decrypt(Pkcs1v15Encrypt, &Base64::decode_vec(test[0]).unwrap())
                .unwrap();
            assert_eq!(out, test[1].as_bytes());
        }
    }

    #[test]
    fn test_encrypt_decrypt_pkcs1v15() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = get_private_key();
        let k = priv_key.size();

        for i in 1..100 {
            let mut input = vec![0u8; i * 8];
            rng.fill_bytes(&mut input);
            if input.len() > k - 11 {
                input = input[0..k - 11].to_vec();
            }

            let pub_key: RsaPublicKey = priv_key.clone().into();
            let ciphertext = encrypt(&mut rng, &pub_key, &input).unwrap();
            assert_ne!(input, ciphertext);

            let blind: bool = rng.next_u32() < (1u32 << 31);
            let blinder = if blind { Some(&mut rng) } else { None };
            let plaintext = decrypt(blinder, &priv_key, &ciphertext).unwrap();
            assert_eq!(input, plaintext);
        }
    }

    #[test]
    fn test_decrypt_pkcs1v15_traits() {
        let priv_key = get_private_key();
        let decrypting_key = DecryptingKey::new(priv_key);

        let tests = [
            [
                "f0f4qsNunKxRgsag5/p3AER7uoqs/Gupe33kuJWGAkLjobLsLszxp7uwVngeoxpDi87rTcJ9y0Sbu2QfnV/KvwEHiuQ8NL1FCRt4ujwgNtQms9XHjkTeLUX9tapoxdA0QhLsjblZFdb3fAvZXHGKPTBdHkxHut6LHG37SxbHeQY=",
                "x",
            ],
            [
                "l+L4+CdrgcFJ9LngppA+o7pZAKmZs4Gu5cRsum7OAji0+XNamTaPKxgtAio5A8ltRLJxrfZnRFOIOyn4964vMIB2YfVG/Vak//kLIn/rbgaVGndmWxQuR6ykEruOuqn5JUqv4JHaW30aDzEkCbpXWpFJ7dhfrWZdSv4XKpt9cY4=",
                "testing.",
            ],
            [
                "JtlpY3lTeCmkRRrIgfuOXH0ubMOL1U/n6nM6r6kF2iuRiFIPapfEzHF2WSvrbxZXa8gzJo1PuAJiJ6Vy90vOWbP43VEXLk5wyGZPePwHQ1WwOcE+6okZ9j9zmAmAnQUyaUjPfhwyDC64ObjiSKeIPCYSsdURy/Z67lcTZ6JJ8+8=",
                "testing.\n",
            ],
            [
                "TcyqI5jrGyln5AspqnvWShPIjKIZtXbNApf9TqAZrsl31RS+k6blEJy6YVZeow9QKis+UyIcz08nMGX/D3lm/JA4bwpyBFAvSFr2MNjNpGh9QqEcGryI0CpLA1fy56x7YGB/Y0eJZXnSj91udGubJTEI9ULTouoFAKxoWq7ioTc=",
                "01234567890123456789012345678901234567890123456789012",
            ],
        ];

        for test in &tests {
            let out = decrypting_key
                .decrypt(&Base64::decode_vec(test[0]).unwrap())
                .unwrap();
            assert_eq!(out, test[1].as_bytes());
        }
    }

    #[test]
    fn test_encrypt_decrypt_pkcs1v15_traits() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let priv_key = get_private_key();
        let k = priv_key.size();
        let decrypting_key = DecryptingKey::new(priv_key);

        for i in 1..100 {
            let mut input = vec![0u8; i * 8];
            rng.fill_bytes(&mut input);
            if input.len() > k - 11 {
                input = input[0..k - 11].to_vec();
            }

            let encrypting_key = decrypting_key.encrypting_key();
            let ciphertext = encrypting_key.encrypt_with_rng(&mut rng, &input).unwrap();
            assert_ne!(input, ciphertext);

            let blind: bool = rng.next_u32() < (1u32 << 31);
            let plaintext = if blind {
                decrypting_key
                    .decrypt_with_rng(&mut rng, &ciphertext)
                    .unwrap()
            } else {
                decrypting_key.decrypt(&ciphertext).unwrap()
            };
            assert_eq!(input, plaintext);
        }
    }

    #[test]
    fn test_sign_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a082d"),
        )];

        for (text, expected) in &tests {
            let digest = Sha1::digest(text.as_bytes()).to_vec();

            let out = priv_key.sign(Pkcs1v15Sign::new::<Sha1>(), &digest).unwrap();
            assert_ne!(hex::encode(&out), hex::encode(&digest));
            assert_eq!(hex::encode(&out), hex::encode(&expected));

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = priv_key
                .sign_with_rng(&mut rng, Pkcs1v15Sign::new::<Sha1>(), &digest)
                .unwrap();
            assert_eq!(hex::encode(&out2), hex::encode(&expected));
        }
    }

    #[test]
    fn test_sign_pkcs1v15_signer() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a082d"),
        )];

        let signing_key = SigningKey::<Sha1>::new(priv_key);

        for (text, expected) in &tests {
            let out = signing_key.sign(text.as_bytes()).to_bytes();
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_ne!(out.as_ref(), &Sha1::digest(text.as_bytes()).to_vec());
            assert_eq!(hex::encode(out.as_ref()), hex::encode(&expected));

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = signing_key
                .sign_with_rng(&mut rng, text.as_bytes())
                .to_bytes();
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_signer_sha2_256() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!("506ea024cfef1a98540d98da07d50a3c08bf03e09f9503e211dada539cd99bcb31e1d439d19182e4ec195496602180874ee1300282f62c74f7d57b9b619ac6092eebb47fedeca1d5d0e63bb5e1f630b06e170a1409fd310e265409b29bb741c37f5400524a6cf18e396ebda1190bc585086e214586d97f0ff822907796bc3879"),
        )];

        let signing_key = SigningKey::<Sha256>::new(priv_key);

        for (text, expected) in &tests {
            let out = signing_key.sign(text.as_bytes()).to_bytes();
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_eq!(hex::encode(out.as_ref()), hex::encode(&expected));

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = signing_key
                .sign_with_rng(&mut rng, text.as_bytes())
                .to_bytes();
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_signer_sha3_256() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!("54e376075e2dfb2c98329102f932f44bc3ae993184742f6572dc5bb86da6d33c966164e377735056e9c56847cf8905ee2f8fd326468571502b3119b8ec8cd30c25a479f2ae204cddff3a0ecc206ce27eca4fdf5d26bad83ef891f9ebb443c6150cae5718ef567f9a8056c8819aad6134ee1d06ed8f150ff573c7938ec568efa1"),
        )];

        let signing_key = SigningKey::<Sha3_256>::new(priv_key);

        for (text, expected) in &tests {
            let out = signing_key.sign(text.as_bytes()).to_bytes();
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_eq!(hex::encode(out.as_ref()), hex::encode(&expected));

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = signing_key
                .sign_with_rng(&mut rng, text.as_bytes())
                .to_bytes();
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_digest_signer() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a082d"),
        )];

        let signing_key = SigningKey::new(priv_key);

        for (text, expected) in &tests {
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());
            let out = signing_key.sign_digest(digest).to_bytes();
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_ne!(out.as_ref(), &Sha1::digest(text.as_bytes()).to_vec());
            assert_eq!(out.as_ref(), expected);

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());
            let out2 = signing_key
                .sign_digest_with_rng(&mut rng, digest)
                .to_bytes();
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_verify_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [
            (
                "Test.\n",
                hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a082d"),
                true,
            ),
            (
                "Test.\n",
                hex!("7919de0402424f7b00f16bda36bb7b4d83dd7fb2cb315d9083f60457063393948dc991cfc8161c7b1266ec373b69bc47554a833f95edab8266385a3a36786fe90f172a9882eddc451f3f678a85ed09c60b26300490dd69ef601849c1f4c01f78046bb8351f3a7888b8ce2213790ab11c5402c4a279cbc9a52e4bc76c4cc41600"),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();

        for (text, sig, expected) in &tests {
            let digest = Sha1::digest(text.as_bytes()).to_vec();
            let result = pub_key.verify(Pkcs1v15Sign::new::<Sha1>(), &digest, sig);

            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[test]
    fn test_verify_pkcs1v15_signer() {
        let priv_key = get_private_key();

        let tests = [
            (
                "Test.\n",
                hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a082d"),
                true,
            ),
            (
                "Test.\n",
                hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a0800"),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key = VerifyingKey::<Sha1>::new(pub_key);

        for (text, sig, expected) in &tests {
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
    }

    #[test]
    fn test_verify_pkcs1v15_digest_signer() {
        let priv_key = get_private_key();

        let tests = [
            (
                "Test.\n",
                hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a082d"),
                true,
            ),
            (
                "Test.\n",
                hex!("2c5954065af5f8c651cc46c49af719507648947a6100ef5c37294939a396c529551bd65c90c4aae0417cd3e621bcfb1d40630b6593a14589b94943efa50342310c23b07aa7acd102dc0b922272db0908509467d56ae3edc5d4ec71ba072f509d0f83d7bc1d88174c0c39a3587963c8625e606c3b99cf9a202da0c0b3677a0800"),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key = VerifyingKey::new(pub_key);

        for (text, sig, expected) in &tests {
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());

            let result =
                verifying_key.verify_digest(digest, &Signature::try_from(sig.as_slice()).unwrap());
            match expected {
                true => result.expect("failed to verify"),
                false => {
                    result.expect_err("expected verifying error");
                }
            }
        }
    }

    #[test]
    fn test_unpadded_signature() {
        let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
        let expected_sig = Base64::decode_vec("E3O2B8toxZitc013ZK0TRP4uo47Clpm/Me/o+Yv5qpU7ZP6x9gFUc8IVv2LkX7kUtkgPl/85f/ehJhcXCsoRoOEbcio8PR3JCt/uPJSzokTvNx7bmYxXTJox6oF3kM3+NI+21jh8CZVyk81lTtFulLfmzAsH4L4w5QJcwWtNJpE=").unwrap();
        let priv_key = get_private_key();

        let sig = priv_key.sign(Pkcs1v15Sign::new_unprefixed(), msg).unwrap();
        assert_eq!(
            Base64::encode_string(&expected_sig),
            Base64::encode_string(&sig)
        );

        let pub_key: RsaPublicKey = priv_key.into();
        pub_key
            .verify(Pkcs1v15Sign::new_unprefixed(), msg, &sig)
            .expect("failed to verify");
    }

    #[test]
    fn test_unpadded_signature_hazmat() {
        let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
        let expected_sig = Base64::decode_vec("E3O2B8toxZitc013ZK0TRP4uo47Clpm/Me/o+Yv5qpU7ZP6x9gFUc8IVv2LkX7kUtkgPl/85f/ehJhcXCsoRoOEbcio8PR3JCt/uPJSzokTvNx7bmYxXTJox6oF3kM3+NI+21jh8CZVyk81lTtFulLfmzAsH4L4w5QJcwWtNJpE=").unwrap();
        let priv_key = get_private_key();

        let signing_key = SigningKey::<Sha1>::new_unprefixed(priv_key);
        let sig = signing_key
            .sign_prehash(msg)
            .expect("Failure during sign")
            .to_bytes();
        assert_eq!(
            Base64::encode_string(sig.as_ref()),
            Base64::encode_string(&expected_sig)
        );

        let verifying_key = signing_key.verifying_key();
        verifying_key
            .verify_prehash(msg, &Signature::try_from(expected_sig.as_slice()).unwrap())
            .expect("failed to verify");
    }
}
