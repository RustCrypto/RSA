use std::ops::Deref;
use num_bigint::traits::ModInverse;
use num_bigint::Sign::Plus;
use num_bigint::{BigInt, BigUint};
use num_traits::{FromPrimitive, One};
use rand::{rngs::ThreadRng, Rng};
#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use digest::Digest;

use crate::algorithms::generate_multi_prime_key;
use crate::errors::{Error, Result as RsaResult};
use crate::hash::Hash;
use crate::pkcs1v15;
use crate::pss;

lazy_static! {
    static ref MIN_PUB_EXPONENT: BigUint = BigUint::from_u64(2).unwrap();
    static ref MAX_PUB_EXPONENT: BigUint = BigUint::from_u64(1 << (31 - 1)).unwrap();
}

/// Represents the public part of an RSA key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct RSAPublicKey {
    n: BigUint,
    e: BigUint,
}

/// Represents a whole RSA key, public and private parts.
#[derive(Debug, Clone, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct RSAPrivateKey {
    /// Public components of the private key.
    pubkey_components: RSAPublicKey,
    /// Private exponent
    d: BigUint,
    /// Prime factors of N, contains >= 2 elements.
    primes: Vec<BigUint>,
    /// precomputed values to speed up private operations
    #[cfg_attr(feature = "serde1", serde(skip))]
    pub(crate) precomputed: Option<PrecomputedValues>,
}

impl PartialEq for RSAPrivateKey {
    #[inline]
    fn eq(&self, other: &RSAPrivateKey) -> bool {
        self.pubkey_components == other.pubkey_components && self.d == other.d && self.primes == other.primes
    }
}

impl Eq for RSAPrivateKey {}

impl Zeroize for RSAPrivateKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
        for prime in self.primes.iter_mut() {
            prime.zeroize();
        }
        self.primes.clear();
        if self.precomputed.is_some() {
            self.precomputed.take().unwrap().zeroize();
        }
    }
}

impl Deref for RSAPrivateKey {
    type Target = RSAPublicKey;
    fn deref(&self) -> &RSAPublicKey {
        &self.pubkey_components
    }
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub(crate) struct PrecomputedValues {
    /// D mod (P-1)
    pub(crate) dp: BigUint,
    /// D mod (Q-1)
    pub(crate) dq: BigUint,
    /// Q^-1 mod P
    pub(crate) qinv: BigInt,

    /// CRTValues is used for the 3rd and subsequent primes. Due to a
    /// historical accident, the CRT for the first two primes is handled
    /// differently in PKCS#1 and interoperability is sufficiently
    /// important that we mirror this.
    pub(crate) crt_values: Vec<CRTValue>,
}

impl Zeroize for PrecomputedValues {
    fn zeroize(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        for val in self.crt_values.iter_mut() {
            val.zeroize();
        }
        self.crt_values.clear();
    }
}

/// Contains the precomputed Chinese remainder theorem values.
#[derive(Debug, Clone, Zeroize)]
pub(crate) struct CRTValue {
    /// D mod (prime - 1)
    pub(crate) exp: BigInt,
    /// R·Coeff ≡ 1 mod Prime.
    pub(crate) coeff: BigInt,
    /// product of primes prior to this (inc p and q)
    pub(crate) r: BigInt,
}

impl From<RSAPrivateKey> for RSAPublicKey {
    fn from(mut private_key: RSAPrivateKey) -> Self {
        let broken_key = RSAPublicKey {
            // Fast, no-allocation creation of a biguint.
            n: BigUint::new_native(Default::default()),
            e: BigUint::new_native(Default::default())
        };
        // The private key is going to get dropped after this, so temporarily
        // making it invalid is fine.
        let pubkey = core::mem::replace(&mut private_key.pubkey_components, broken_key);
        pubkey
    }
}

impl RSAPublicKey {
    /// Create a new key from its components.
    pub fn new(n: BigUint, e: BigUint) -> RsaResult<Self> {
        let k = RSAPublicKey { n, e };
        check_public(&k)?;

        Ok(k)
    }

    /// Returns the modulus of the key.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Returns the public exponent of the key.
    pub fn e(&self) -> &BigUint {
        &self.e
    }

    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    pub fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }

    /// Encrypt the given message, using the PKCS1v15 padding scheme.
    pub fn encrypt_pkcs1v15<R: Rng>(&self, rng: &mut R, msg: &[u8]) -> RsaResult<Vec<u8>> {
        pkcs1v15::encrypt(rng, self, msg)
    }

    /// Verify a message signed with the PKCS1v15 padding scheme.
    /// `hashed` must be the result of hashing the input using the hashing function
    /// identified using the ASN1 prefix in `hash_asn1_prefix`.
    /// If the message is valid `Ok(())` is returned, otherwiese an `Err` indicating failure.
    pub fn verify_pkcs1v15<H: Hash>(
        &self,
        hash: Option<&H>,
        hashed: &[u8],
        sig: &[u8],
    ) -> RsaResult<()> {
        pkcs1v15::verify(self, hash, hashed, sig)
    }

    /// Verify that the given signature is valid using the PSS padding scheme.
    ///
    /// The first parameter should be a pre-hashed message, using D as the
    /// hashing scheme.
    ///
    /// The salt length is auto-detected.
    pub fn verify_pss<D: Digest>(
        &self,
        hashed: &[u8],
        sig: &[u8]
    ) -> RsaResult<()> {
        pss::verify::<D>(self, hashed, sig)
    }
}

impl RSAPrivateKey {
    /// Generate a new RSA key pair of the given bit size using the passed in `rng`.
    pub fn new<R: Rng>(rng: &mut R, bit_size: usize) -> RsaResult<RSAPrivateKey> {
        generate_multi_prime_key(rng, 2, bit_size)
    }

    /// Constructs an RSA key pair from the individual components.
    pub fn from_components(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        primes: Vec<BigUint>,
    ) -> RSAPrivateKey {
        let mut k = RSAPrivateKey {
            pubkey_components: RSAPublicKey {
                n, e
            },
            d,
            primes,
            precomputed: None,
        };

        k.precompute();

        k
    }

    /// Get the public key from the private key, cloning `n` and `e`.
    ///
    /// Generally this is not needed since `RSAPrivateKey` implements the `PublicKey` trait,
    /// but it can occationally be useful to discard the private information entirely.
    pub fn to_public_key(&self) -> RSAPublicKey {
        // Safe to unwrap since n and e are already verified.
        RSAPublicKey::new(self.n().clone(), self.e().clone()).unwrap()
    }

    /// Performs some calculations to speed up private key operations.
    pub fn precompute(&mut self) {
        if self.precomputed.is_some() {
            return;
        }

        let dp = &self.d % (&self.primes[0] - BigUint::one());
        let dq = &self.d % (&self.primes[1] - BigUint::one());
        let qinv = self.primes[1]
            .clone()
            .mod_inverse(&self.primes[0])
            .expect("invalid prime");

        let mut r: BigUint = &self.primes[0] * &self.primes[1];
        let crt_values: Vec<CRTValue> = self
            .primes
            .iter()
            .skip(2)
            .map(|prime| {
                let res = CRTValue {
                    exp: BigInt::from_biguint(Plus, &self.d % (prime - BigUint::one())),
                    r: BigInt::from_biguint(Plus, r.clone()),
                    coeff: BigInt::from_biguint(
                        Plus,
                        r.clone()
                            .mod_inverse(prime)
                            .expect("invalid coeff")
                            .to_biguint()
                            .unwrap(),
                    ),
                };
                r *= prime;

                res
            })
            .collect();

        self.precomputed = Some(PrecomputedValues {
            dp,
            dq,
            qinv,
            crt_values,
        });
    }

    /// Returns the private exponent of the key.
    pub fn d(&self) -> &BigUint {
        &self.d
    }

    /// Returns the prime factors.
    pub fn primes(&self) -> &[BigUint] {
        &self.primes
    }

    /// Performs basic sanity checks on the key.
    /// Returns `Ok(())` if everything is good, otherwise an approriate error.
    pub fn validate(&self) -> RsaResult<()> {
        check_public(self)?;

        // Check that Πprimes == n.
        let mut m = BigUint::one();
        for prime in &self.primes {
            // Any primes ≤ 1 will cause divide-by-zero panics later.
            if *prime < BigUint::one() {
                return Err(Error::InvalidPrime);
            }
            m *= prime;
        }
        if m != self.n {
            return Err(Error::InvalidModulus);
        }

        // Check that de ≡ 1 mod p-1, for each prime.
        // This implies that e is coprime to each p-1 as e has a multiplicative
        // inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) =
        // exponent(ℤ/nℤ). It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1
        // mod p. Thus a^de ≡ a mod n for all a coprime to n, as required.
        let mut de = self.e.clone();
        de *= self.d.clone();
        for prime in &self.primes {
            let congruence: BigUint = &de % (prime - BigUint::one());
            if !congruence.is_one() {
                return Err(Error::InvalidExponent);
            }
        }

        Ok(())
    }

    /// Decrypt the given message, using the PKCS1v15 padding scheme.
    pub fn decrypt_pkcs1v15(&self, ciphertext: &[u8]) -> RsaResult<Vec<u8>> {
        pkcs1v15::decrypt::<ThreadRng>(None, self, ciphertext)
    }

    /// Decrypt the given message, using the PKCS1v15 padding scheme.
    ///
    /// Uses `rng` to blind the decryption process.
    pub fn decrypt_pkcs1v15_blinded<R: Rng>(
        &self,
        rng: &mut R,
        ciphertext: &[u8],
    ) -> RsaResult<Vec<u8>> {
        pkcs1v15::decrypt(Some(rng), self, ciphertext)
    }

    /// Sign the given digest using the PKCS1v15 padding scheme.
    pub fn sign_pkcs1v15<H: Hash>(
        &self,
        hash: Option<&H>,
        digest: &[u8],
    ) -> RsaResult<Vec<u8>> {
        pkcs1v15::sign::<ThreadRng, _>(None, self, hash, digest)
    }

    /// Sign the given digest using the PKCS1v15 padding scheme.
    ///
    /// Use `rng` for blinding.
    pub fn sign_pkcs1v15_blinded<H: Hash, R: Rng>(
        &self,
        rng: &mut R,
        hash: Option<&H>,
        digest: &[u8],
    ) -> RsaResult<Vec<u8>> {
        pkcs1v15::sign(Some(rng), self, hash, digest)
    }

    /// Sign the given pre-hashed message using the PSS padding scheme. The
    /// message should be hashed using the Digest algorithm passed as a generic
    /// argument.
    ///
    /// RNG is used for PSS salt generation, and if `blind` is true, it will
    /// also be used to blind the RSA encryption.
    ///
    /// The length of the salt can be controlled with the salt_len parameter. If
    /// it is None, then it will be calculated to be as large as possible.
    pub fn sign_pss<D: Digest, R: Rng>(
        &self,
        rng: &mut R,
        digest: &[u8],
        salt_len: Option<usize>,
        blind: bool
    ) -> RsaResult<Vec<u8>> {
        pss::sign::<R, D>(rng, self, digest, salt_len, blind)
    }
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
pub fn check_public(public_key: &RSAPublicKey) -> RsaResult<()> {
    if public_key.e() < &*MIN_PUB_EXPONENT {
        return Err(Error::PublicExponentTooSmall);
    }

    if public_key.e() > &*MAX_PUB_EXPONENT {
        return Err(Error::PublicExponentTooLarge);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internals;
    use num_traits::{FromPrimitive, ToPrimitive};
    use rand::{rngs::ThreadRng, thread_rng};

    #[test]
    fn test_from_into() {
        let private_key = RSAPrivateKey {
            pubkey_components: RSAPublicKey {
                n: BigUint::from_u64(100).unwrap(),
                e: BigUint::from_u64(200).unwrap(),
            },
            d: BigUint::from_u64(123).unwrap(),
            primes: vec![],
            precomputed: None,
        };
        let public_key: RSAPublicKey = private_key.into();

        assert_eq!(public_key.n().to_u64(), Some(100));
        assert_eq!(public_key.e().to_u64(), Some(200));
    }

    fn test_key_basics(private_key: &RSAPrivateKey) {
        private_key.validate().expect("invalid private key");

        assert!(
            private_key.d() < private_key.n(),
            "private exponent too large"
        );

        let pub_key: RSAPublicKey = private_key.clone().into();
        let m = BigUint::from_u64(42).expect("invalid 42");
        let c = internals::encrypt(&pub_key, &m);
        let m2 = internals::decrypt::<ThreadRng>(None, &private_key, &c)
            .expect("unable to decrypt without blinding");
        assert_eq!(m, m2);
        let mut rng = thread_rng();
        let m3 = internals::decrypt(Some(&mut rng), &private_key, &c)
            .expect("unable to decrypt with blinding");
        assert_eq!(m, m3);
    }

    macro_rules! key_generation {
        ($name:ident, $multi:expr, $size:expr) => {
            #[test]
            fn $name() {
                let mut rng = thread_rng();

                for _ in 0..10 {
                    let private_key = if $multi == 2 {
                        RSAPrivateKey::new(&mut rng, $size).expect("failed to generate key")
                    } else {
                        generate_multi_prime_key(&mut rng, $multi, $size).unwrap()
                    };
                    assert_eq!(private_key.n().bits(), $size);

                    test_key_basics(&private_key);
                }
            }
        };
    }

    key_generation!(key_generation_128, 2, 128);
    key_generation!(key_generation_1024, 2, 1024);

    key_generation!(key_generation_multi_3_256, 3, 256);

    key_generation!(key_generation_multi_4_64, 4, 64);

    key_generation!(key_generation_multi_5_64, 5, 64);
    key_generation!(key_generation_multi_8_576, 8, 576);
    key_generation!(key_generation_multi_16_1024, 16, 1024);

    #[test]
    fn test_impossible_keys() {
        // make sure not infinite loops are hit here.
        let mut rng = thread_rng();
        for i in 0..32 {
            let _ = RSAPrivateKey::new(&mut rng, i).is_err();
            let _ = generate_multi_prime_key(&mut rng, 3, i);
            let _ = generate_multi_prime_key(&mut rng, 4, i);
            let _ = generate_multi_prime_key(&mut rng, 5, i);
        }
    }

    #[test]
    fn test_negative_decryption_value() {
        let private_key = RSAPrivateKey::from_components(
            BigUint::from_bytes_le(&vec![
                99, 192, 208, 179, 0, 220, 7, 29, 49, 151, 75, 107, 75, 73, 200, 180,
            ]),
            BigUint::from_bytes_le(&vec![1, 0, 1]),
            BigUint::from_bytes_le(&vec![
                81, 163, 254, 144, 171, 159, 144, 42, 244, 133, 51, 249, 28, 12, 63, 65,
            ]),
            vec![
                BigUint::from_bytes_le(&vec![105, 101, 60, 173, 19, 153, 3, 192]),
                BigUint::from_bytes_le(&vec![235, 65, 160, 134, 32, 136, 6, 241]),
            ],
        );

        for _ in 0..1000 {
            test_key_basics(&private_key);
        }
    }

    #[test]
    #[cfg(feature = "serde1")]
    fn test_serde() {
        use rand::{SeedableRng, XorShiftRng};
        use serde_test::{assert_tokens, Token};

        let mut rng = XorShiftRng::from_seed([1; 16]);
        let priv_key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");

        let priv_tokens = [
            Token::Struct {
                name: "RSAPrivateKey",
                len: 4,
            },
            Token::Str("n"),
            Token::Seq { len: Some(2) },
            Token::U32(1296829443),
            Token::U32(2444363981),
            Token::SeqEnd,
            Token::Str("e"),
            Token::Seq { len: Some(1) },
            Token::U32(65537),
            Token::SeqEnd,
            Token::Str("d"),
            Token::Seq { len: Some(2) },
            Token::U32(298985985),
            Token::U32(2349628418),
            Token::SeqEnd,
            Token::Str("primes"),
            Token::Seq { len: Some(2) },
            Token::Seq { len: Some(1) },
            Token::U32(3238068481),
            Token::SeqEnd,
            Token::Seq { len: Some(1) },
            Token::U32(3242199299),
            Token::SeqEnd,
            Token::SeqEnd,
            Token::StructEnd,
        ];
        assert_tokens(&priv_key, &priv_tokens);

        let priv_tokens = [
            Token::Struct {
                name: "RSAPublicKey",
                len: 2,
            },
            Token::Str("n"),
            Token::Seq { len: Some(2) },
            Token::U32(1296829443),
            Token::U32(2444363981),
            Token::SeqEnd,
            Token::Str("e"),
            Token::Seq { len: Some(1) },
            Token::U32(65537),
            Token::SeqEnd,
            Token::StructEnd,
        ];
        assert_tokens(&RSAPublicKey::from(priv_key), &priv_tokens);
    }
}
