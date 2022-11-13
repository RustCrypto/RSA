//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

use alloc::vec::Vec;
use core::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};
use core::marker::PhantomData;
use core::ops::Deref;
use digest::Digest;
use pkcs8::{AssociatedOid, Document, EncodePrivateKey, EncodePublicKey, SecretDocument};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "hazmat")]
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::{
    DigestSigner, DigestVerifier, RandomizedDigestSigner, RandomizedSigner,
    Signature as SignSignature, Signer, Verifier,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::dummy_rng::DummyRng;
use crate::errors::{Error, Result};
use crate::key::{self, PrivateKey, PublicKey};
use crate::{RsaPrivateKey, RsaPublicKey};

/// PKCS#1 v1.5 signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Clone)]
pub struct Signature {
    bytes: Vec<u8>,
}

impl signature::Signature for Signature {
    fn from_bytes(bytes: &[u8]) -> signature::Result<Self> {
        Ok(Signature {
            bytes: bytes.into(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl From<Vec<u8>> for Signature {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Signature {}

impl Debug for Signature {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> core::result::Result<(), core::fmt::Error> {
        fmt.debug_list().entries(self.as_bytes().iter()).finish()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl LowerHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:X}", self)
    }
}

/// Encrypts the given message with RSA and the padding
/// scheme from PKCS#1 v1.5.  The message must be no longer than the
/// length of the public modulus minus 11 bytes.
#[inline]
pub(crate) fn encrypt<R: RngCore + CryptoRng, PK: PublicKey>(
    rng: &mut R,
    pub_key: &PK,
    msg: &[u8],
) -> Result<Vec<u8>> {
    key::check_public(pub_key)?;

    let k = pub_key.size();
    if msg.len() > k - 11 {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let mut em = Zeroizing::new(vec![0u8; k]);
    em[1] = 2;
    non_zero_random_bytes(rng, &mut em[2..k - msg.len() - 1]);
    em[k - msg.len() - 1] = 0;
    em[k - msg.len()..].copy_from_slice(msg);

    pub_key.raw_encryption_primitive(&em, pub_key.size())
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
pub(crate) fn decrypt<R: RngCore + CryptoRng, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    key::check_public(priv_key)?;

    let (valid, out, index) = decrypt_inner(rng, priv_key, ciphertext)?;
    if valid == 0 {
        return Err(Error::Decryption);
    }

    Ok(out[index as usize..].to_vec())
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
pub(crate) fn sign<R: RngCore + CryptoRng, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    prefix: &[u8],
    hashed: &[u8],
) -> Result<Vec<u8>> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    let k = priv_key.size();
    if k < t_len + 11 {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    priv_key.raw_decryption_primitive(rng, &em, priv_key.size())
}

/// Verifies an RSA PKCS#1 v1.5 signature.
#[inline]
pub(crate) fn verify<PK: PublicKey>(
    pub_key: &PK,
    prefix: &[u8],
    hashed: &[u8],
    sig: &[u8],
) -> Result<()> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    let k = pub_key.size();
    if k < t_len + 11 {
        return Err(Error::Verification);
    }

    let em = pub_key.raw_encryption_primitive(sig, pub_key.size())?;

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut ok = em[0].ct_eq(&0u8);
    ok &= em[1].ct_eq(&1u8);
    ok &= em[k - hash_len..k].ct_eq(hashed);
    ok &= em[k - t_len..k - hash_len].ct_eq(prefix);
    ok &= em[k - t_len - 1].ct_eq(&0u8);

    for el in em.iter().skip(2).take(k - t_len - 3) {
        ok &= el.ct_eq(&0xff)
    }

    if ok.unwrap_u8() != 1 {
        return Err(Error::Verification);
    }

    Ok(())
}

/// prefix = 0x30 <oid_len + 8 + digest_len> 0x30 <oid_len + 4> 0x06 <oid_len> oid 0x05 0x00 0x04 <digest_len>
#[inline]
pub(crate) fn generate_prefix<D>() -> Vec<u8>
where
    D: Digest + AssociatedOid,
{
    let oid = D::OID.as_bytes();
    let oid_len = oid.len() as u8;
    let digest_len = <D as Digest>::output_size() as u8;
    let mut v = vec![
        0x30,
        oid_len + 8 + digest_len,
        0x30,
        oid_len + 4,
        0x6,
        oid_len,
    ];
    v.extend_from_slice(oid);
    v.extend_from_slice(&[0x05, 0x00, 0x04, digest_len]);
    v
}

/// Decrypts ciphertext using `priv_key` and blinds the operation if
/// `rng` is given. It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured. In either case, the plaintext is
/// returned in em so that it may be read independently of whether it was valid
/// in order to maintain constant memory access patterns. If the plaintext was
/// valid then index contains the index of the original message in em.
#[inline]
fn decrypt_inner<R: RngCore + CryptoRng, SK: PrivateKey>(
    rng: Option<&mut R>,
    priv_key: &SK,
    ciphertext: &[u8],
) -> Result<(u8, Vec<u8>, u32)> {
    let k = priv_key.size();
    if k < 11 {
        return Err(Error::Decryption);
    }

    let em = priv_key.raw_decryption_primitive(rng, ciphertext, priv_key.size())?;

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   looking_for_index: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut looking_for_index = 1u8;
    let mut index = 0u32;

    for (i, el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.conditional_assign(&(i as u32), Choice::from(looking_for_index) & equals0);
        looking_for_index.conditional_assign(&0u8, equals0);
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    // TODO: WARNING: THIS MUST BE CONSTANT TIME CHECK:
    // Ref: https://github.com/dalek-cryptography/subtle/issues/20
    // This is currently copy & paste from the constant time impl in
    // go, but very likely not sufficient.
    let valid_ps = Choice::from((((2i32 + 8i32 - index as i32 - 1i32) >> 31) & 1) as u8);
    let valid =
        first_byte_is_zero & second_byte_is_two & Choice::from(!looking_for_index & 1) & valid_ps;
    index = u32::conditional_select(&0, &(index + 1), valid);

    Ok((valid.unwrap_u8(), em, index))
}

/// Fills the provided slice with random values, which are guaranteed
/// to not be zero.
#[inline]
fn non_zero_random_bytes<R: RngCore + CryptoRng>(rng: &mut R, data: &mut [u8]) {
    rng.fill_bytes(data);

    for el in data {
        if *el == 0u8 {
            // TODO: break after a certain amount of time
            while *el == 0u8 {
                rng.fill_bytes(core::slice::from_mut(el));
            }
        }
    }
}

/// Signing key for PKCS#1 v1.5 signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug, Clone)]
pub struct SigningKey<D>
where
    D: Digest,
{
    inner: RsaPrivateKey,
    prefix: Vec<u8>,
    phantom: PhantomData<D>,
}

impl<D> SigningKey<D>
where
    D: Digest,
{
    /// Create a new signing key from the give RSA private key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            prefix: Vec::new(),
            phantom: Default::default(),
        }
    }

    pub(crate) fn key(&self) -> &RsaPrivateKey {
        &self.inner
    }

    pub(crate) fn prefix(&self) -> Vec<u8> {
        self.prefix.clone()
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

impl<D> SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    /// Create a new verifying key with a prefix for the digest `D`.
    pub fn new_with_prefix(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            prefix: generate_prefix::<D>(),
            phantom: Default::default(),
        }
    }
}

impl<D> AsRef<RsaPrivateKey> for SigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
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

impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        sign::<DummyRng, _>(None, &self.inner, &self.prefix, &D::digest(msg))
            .map(|v| v.into())
            .map_err(|e| e.into())
    }
}

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        sign(Some(&mut rng), &self.inner, &self.prefix, &D::digest(msg))
            .map(|v| v.into())
            .map_err(|e| e.into())
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign_digest(&self, digest: D) -> signature::Result<Signature> {
        sign::<DummyRng, _>(None, &self.inner, &self.prefix, &digest.finalize())
            .map(|v| v.into())
            .map_err(|e| e.into())
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign_digest_with_rng(
        &self,
        mut rng: impl CryptoRng + RngCore,
        digest: D,
    ) -> signature::Result<Signature> {
        sign(
            Some(&mut rng),
            &self.inner,
            &self.prefix,
            &digest.finalize(),
        )
        .map(|v| v.into())
        .map_err(|e| e.into())
    }
}

#[cfg(feature = "hazmat")]
impl<D> PrehashSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        sign::<DummyRng, _>(None, &self.inner, &self.prefix, prehash)
            .map(|v| v.into())
            .map_err(|e| e.into())
    }
}

/// Verifying key for PKCS#1 v1.5 signatures as described in [RFC8017 § 8.2].
///
/// [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
#[derive(Debug, Clone)]
pub struct VerifyingKey<D>
where
    D: Digest,
{
    inner: RsaPublicKey,
    prefix: Vec<u8>,
    phantom: PhantomData<D>,
}

impl<D> VerifyingKey<D>
where
    D: Digest,
{
    /// Create a new verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            prefix: Vec::new(),
            phantom: Default::default(),
        }
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

impl<D> VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    /// Create a new verifying key with a prefix for the digest `D`.
    pub fn new_with_prefix(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            prefix: generate_prefix::<D>(),
            phantom: Default::default(),
        }
    }
}

impl<D> AsRef<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPublicKey {
        &self.inner
    }
}

impl<D> From<SigningKey<D>> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: SigningKey<D>) -> Self {
        Self {
            inner: key.key().into(),
            prefix: key.prefix(),
            phantom: Default::default(),
        }
    }
}

impl<D> From<&SigningKey<D>> for VerifyingKey<D>
where
    D: Digest,
{
    fn from(key: &SigningKey<D>) -> Self {
        Self {
            inner: key.key().into(),
            prefix: key.prefix(),
            phantom: Default::default(),
        }
    }
}

impl<D> Verifier<Signature> for VerifyingKey<D>
where
    D: Digest,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> signature::Result<()> {
        verify(
            &self.inner,
            &self.prefix,
            &D::digest(msg),
            signature.as_ref(),
        )
        .map_err(|e| e.into())
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey<D>
where
    D: Digest,
{
    fn verify_digest(&self, digest: D, signature: &Signature) -> signature::Result<()> {
        verify(
            &self.inner,
            &self.prefix,
            &digest.finalize(),
            signature.as_ref(),
        )
        .map_err(|e| e.into())
    }
}

#[cfg(feature = "hazmat")]
impl<D> PrehashVerifier<Signature> for VerifyingKey<D>
where
    D: Digest,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> signature::Result<()> {
        verify(&self.inner, &self.prefix, prehash, signature.as_ref()).map_err(|e| e.into())
    }
}

impl<D> EncodePublicKey for VerifyingKey<D>
where
    D: Digest,
{
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        self.inner.to_public_key_der()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::{Base64, Encoding};
    use hex_literal::hex;
    use num_bigint::BigUint;
    use num_traits::FromPrimitive;
    use num_traits::Num;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use sha1::{Digest, Sha1};
    use sha2::Sha256;
    use sha3::Sha3_256;
    use signature::{RandomizedSigner, Signature, Signer, Verifier};

    use crate::{PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_non_zero_bytes() {
        for _ in 0..10 {
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut b = vec![0u8; 512];
            non_zero_random_bytes(&mut rng, &mut b);
            for el in &b {
                assert_ne!(*el, 0u8);
            }
        }
    }

    fn get_private_key() -> RsaPrivateKey {
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

        RsaPrivateKey::from_components(
            BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
            BigUint::from_u64(65537).unwrap(),
            BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
            vec![
                BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443",10).unwrap(),
                BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap()
            ],
        ).unwrap()
    }

    #[test]
    fn test_decrypt_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [[
	    "gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==",
	    "x",
	], [
	    "Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==",
	    "testing.",
	], [
	    "arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==",
	    "testing.\n",
	], [
	"WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==",
		"01234567890123456789012345678901234567890123456789012",
	]];

        for test in &tests {
            let out = priv_key
                .decrypt(
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    &Base64::decode_vec(test[0]).unwrap(),
                )
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
    fn test_sign_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!(
                "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
            ),
        )];

        for (text, expected) in &tests {
            let digest = Sha1::digest(text.as_bytes()).to_vec();

            let out = priv_key
                .sign(PaddingScheme::new_pkcs1v15_sign::<Sha1>(), &digest)
                .unwrap();
            assert_ne!(out, digest);
            assert_eq!(out, expected);

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = priv_key
                .sign_blinded(
                    &mut rng,
                    PaddingScheme::new_pkcs1v15_sign::<Sha1>(),
                    &digest,
                )
                .unwrap();
            assert_eq!(out2, expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_signer() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!(
                "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
            ),
        )];

        let signing_key = SigningKey::<Sha1>::new_with_prefix(priv_key);

        for (text, expected) in &tests {
            let out = signing_key.sign(text.as_bytes());
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_ne!(out.as_ref(), &Sha1::digest(text.as_bytes()).to_vec());
            assert_eq!(out.as_ref(), expected);

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = signing_key.sign_with_rng(&mut rng, text.as_bytes());
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_signer_sha2_256() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!(
                "2ffae3f3e130287b3a1dcb320e46f52e8f3f7969b646932273a7e3a6f2a182ea"
                "02d42875a7ffa4a148aa311f9e4b562e4e13a2223fb15f4e5bf5f2b206d9451b"
            ),
        )];

        let signing_key = SigningKey::<Sha256>::new_with_prefix(priv_key);

        for (text, expected) in &tests {
            let out = signing_key.sign(text.as_bytes());
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_eq!(out.as_ref(), expected);

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = signing_key.sign_with_rng(&mut rng, text.as_bytes());
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_signer_sha3_256() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!(
                "55e9fba3354dfb51d2c8111794ea552c86afc2cab154652c03324df8c2c51ba7"
                "2ff7c14de59a6f9ba50d90c13a7537cc3011948369f1f0ec4a49d21eb7e723f9"
            ),
        )];

        let signing_key = SigningKey::<Sha3_256>::new_with_prefix(priv_key);

        for (text, expected) in &tests {
            let out = signing_key.sign(text.as_bytes());
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_eq!(out.as_ref(), expected);

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let out2 = signing_key.sign_with_rng(&mut rng, text.as_bytes());
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_sign_pkcs1v15_digest_signer() {
        let priv_key = get_private_key();

        let tests = [(
            "Test.\n",
            hex!(
                "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
            ),
        )];

        let signing_key = SigningKey::new_with_prefix(priv_key);

        for (text, expected) in &tests {
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());
            let out = signing_key.sign_digest(digest);
            assert_ne!(out.as_ref(), text.as_bytes());
            assert_ne!(out.as_ref(), &Sha1::digest(text.as_bytes()).to_vec());
            assert_eq!(out.as_ref(), expected);

            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());
            let out2 = signing_key.sign_digest_with_rng(&mut rng, digest);
            assert_eq!(out2.as_ref(), expected);
        }
    }

    #[test]
    fn test_verify_pkcs1v15() {
        let priv_key = get_private_key();

        let tests = [
            (
                "Test.\n",
                hex!(
                    "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                    "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
                ),
                true,
            ),
            (
                "Test.\n",
                hex!(
                    "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                    "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362af"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();

        for (text, sig, expected) in &tests {
            let digest = Sha1::digest(text.as_bytes()).to_vec();

            let result = pub_key.verify(PaddingScheme::new_pkcs1v15_sign::<Sha1>(), &digest, sig);
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
                hex!(
                    "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                    "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
                ),
                true,
            ),
            (
                "Test.\n",
                hex!(
                    "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                    "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362af"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key = VerifyingKey::<Sha1>::new_with_prefix(pub_key);

        for (text, sig, expected) in &tests {
            let result =
                verifying_key.verify(text.as_bytes(), &Signature::from_bytes(sig).unwrap());
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
                hex!(
                    "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                    "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
                ),
                true,
            ),
            (
                "Test.\n",
                hex!(
                    "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e33"
                    "6ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362af"
                ),
                false,
            ),
        ];
        let pub_key: RsaPublicKey = priv_key.into();
        let verifying_key = VerifyingKey::new_with_prefix(pub_key);

        for (text, sig, expected) in &tests {
            let mut digest = Sha1::new();
            digest.update(text.as_bytes());
            let result = verifying_key.verify_digest(digest, &Signature::from_bytes(sig).unwrap());
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
        let expected_sig = Base64::decode_vec("pX4DR8azytjdQ1rtUiC040FjkepuQut5q2ZFX1pTjBrOVKNjgsCDyiJDGZTCNoh9qpXYbhl7iEym30BWWwuiZg==").unwrap();
        let priv_key = get_private_key();

        let sig = priv_key
            .sign(PaddingScheme::new_pkcs1v15_sign_raw(), msg)
            .unwrap();
        assert_eq!(expected_sig, sig);

        let pub_key: RsaPublicKey = priv_key.into();
        pub_key
            .verify(PaddingScheme::new_pkcs1v15_sign_raw(), msg, &sig)
            .expect("failed to verify");
    }

    #[cfg(feature = "hazmat")]
    #[test]
    fn test_unpadded_signature_hazmat() {
        let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
        let expected_sig = Base64::decode_vec("pX4DR8azytjdQ1rtUiC040FjkepuQut5q2ZFX1pTjBrOVKNjgsCDyiJDGZTCNoh9qpXYbhl7iEym30BWWwuiZg==").unwrap();
        let priv_key = get_private_key();

        let signing_key = SigningKey::<Sha1>::new(priv_key);
        let sig = signing_key.sign_prehash(msg).expect("Failure during sign");
        assert_eq!(sig.as_ref(), expected_sig);

        let verifying_key: VerifyingKey<_> = (&signing_key).into();
        verifying_key
            .verify_prehash(msg, &Signature::from_bytes(&expected_sig).unwrap())
            .expect("failed to verify");
    }
}
