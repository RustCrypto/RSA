use num_bigint::traits::ModInverse;
use num_bigint::Sign::Plus;
use num_bigint::{BigInt, BigUint};
use num_traits::{FromPrimitive, One};
use rand::{rngs::ThreadRng, Rng};
#[cfg(feature = "serde1")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::algorithms::generate_multi_prime_key;
use crate::errors::{Error, Result};
use crate::hash::{Hash,Hashes};
use crate::padding::PaddingScheme;
use crate::pkcs1v15;
use crate::oaep;

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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde1", derive(Serialize, Deserialize))]
pub struct RSAPrivateKey {
    /// Modulus
    n: BigUint,
    /// Public exponent
    e: BigUint,
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
        self.n == other.n && self.e == other.e && self.d == other.d && self.primes == other.primes
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

impl Drop for RSAPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone)]
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

impl Drop for PrecomputedValues {
    fn drop(&mut self) {
        self.zeroize();
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
    fn from(private_key: RSAPrivateKey) -> Self {
        let n = private_key.n.clone();
        let e = private_key.e.clone();

        RSAPublicKey { n, e }
    }
}

/// Generic trait for operations on a public key.
pub trait PublicKey {
    /// Returns the modulus of the key.
    fn n(&self) -> &BigUint;
    /// Returns the public exponent of the key.
    fn e(&self) -> &BigUint;
    /// Returns the modulus size in bytes. Raw signatures and ciphertexts for
    /// or by this public key will have the same size.
    fn size(&self) -> usize {
        (self.n().bits() + 7) / 8
    }

    /// Encrypt the given message.
    fn encrypt<R: Rng>(&self, rng: &mut R, padding: PaddingScheme, msg: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signed message.
    /// `hashed`must be the result of hashing the input using the hashing function
    /// passed in through `hash`.
    /// If the message is valid `Ok(())` is returned, otherwiese an `Err` indicating failure.
    fn verify<H: Hash>(
        &self,
        padding: PaddingScheme,
        hash: Option<&H>,
        hashed: &[u8],
        sig: &[u8],
    ) -> Result<()>;
}

impl PublicKey for RSAPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }
    fn encrypt<R: Rng>(&self, rng: &mut R, padding: PaddingScheme, msg: &[u8]) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::encrypt(rng, self, msg),
            PaddingScheme::OAEP => oaep::encrypt(rng,self,msg,oaep::OaepOptions {
                hash: Hashes::SHA1,
                label: None,
            }),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }

    fn verify<H: Hash>(
        &self,
        padding: PaddingScheme,
        hash: Option<&H>,
        hashed: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::verify(self, hash, hashed, sig),
            PaddingScheme::PSS => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }
}

impl RSAPublicKey {
    /// Create a new key from its components.
    pub fn new(n: BigUint, e: BigUint) -> Result<Self> {
        let k = RSAPublicKey { n, e };
        check_public(&k)?;

        Ok(k)
    }
}

impl<'a> PublicKey for &'a RSAPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }

    fn encrypt<R: Rng>(&self, rng: &mut R, padding: PaddingScheme, msg: &[u8]) -> Result<Vec<u8>> {
        (*self).encrypt(rng, padding, msg)
    }

    fn verify<H: Hash>(
        &self,
        padding: PaddingScheme,
        hash: Option<&H>,
        hashed: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        (*self).verify(padding, hash, hashed, sig)
    }
}

impl PublicKey for RSAPrivateKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }

    fn encrypt<R: Rng>(&self, rng: &mut R, padding: PaddingScheme, msg: &[u8]) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::encrypt(rng, self, msg),
            PaddingScheme::OAEP => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }

    fn verify<H: Hash>(
        &self,
        padding: PaddingScheme,
        hash: Option<&H>,
        hashed: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::verify(self, hash, hashed, sig),
            PaddingScheme::PSS => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }
}

impl<'a> PublicKey for &'a RSAPrivateKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> &BigUint {
        &self.e
    }

    fn encrypt<R: Rng>(&self, rng: &mut R, padding: PaddingScheme, msg: &[u8]) -> Result<Vec<u8>> {
        (*self).encrypt(rng, padding, msg)
    }

    fn verify<H: Hash>(
        &self,
        padding: PaddingScheme,
        hash: Option<&H>,
        hashed: &[u8],
        sig: &[u8],
    ) -> Result<()> {
        (*self).verify(padding, hash, hashed, sig)
    }
}

impl RSAPrivateKey {
    /// Generate a new RSA key pair of the given bit size using the passed in `rng`.
    pub fn new<R: Rng>(rng: &mut R, bit_size: usize) -> Result<RSAPrivateKey> {
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
            n,
            e,
            d,
            primes,
            precomputed: None,
        };

        // precompute when possible, ignore error otherwise.
        let _ = k.precompute();

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
    pub fn precompute(&mut self) -> Result<()> {
        if self.precomputed.is_some() {
            return Ok(());
        }

        let dp = &self.d % (&self.primes[0] - BigUint::one());
        let dq = &self.d % (&self.primes[1] - BigUint::one());
        let qinv = self.primes[1]
            .clone()
            .mod_inverse(&self.primes[0])
            .ok_or(Error::InvalidPrime)?;

        let mut r: BigUint = &self.primes[0] * &self.primes[1];
        let crt_values: Vec<CRTValue> = {
            let mut values = Vec::with_capacity(self.primes.len() - 2);
            for prime in &self.primes[2..] {
                let res = CRTValue {
                    exp: BigInt::from_biguint(Plus, &self.d % (prime - BigUint::one())),
                    r: BigInt::from_biguint(Plus, r.clone()),
                    coeff: BigInt::from_biguint(
                        Plus,
                        r.clone()
                            .mod_inverse(prime)
                            .ok_or(Error::InvalidCoefficient)?
                            .to_biguint()
                            .unwrap(),
                    ),
                };
                r *= prime;

                values.push(res);
            }
            values
        };

        self.precomputed = Some(PrecomputedValues {
            dp,
            dq,
            qinv,
            crt_values,
        });

        Ok(())
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
    pub fn validate(&self) -> Result<()> {
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

    /// Decrypt the given message.
    pub fn decrypt(&self, padding: PaddingScheme, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match padding {
            // need to pass any Rng as the type arg, so the type checker is happy, it is not actually used for anything
            PaddingScheme::PKCS1v15 => pkcs1v15::decrypt::<ThreadRng>(None, self, ciphertext),
            PaddingScheme::OAEP => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }

    /// Decrypt the given message.
    /// Uses `rng` to blind the decryption process.
    pub fn decrypt_blinded<R: Rng>(
        &self,
        rng: &mut R,
        padding: PaddingScheme,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::decrypt(Some(rng), self, ciphertext),
            PaddingScheme::OAEP => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }

    /// Sign the given digest.
    pub fn sign<H: Hash>(
        &self,
        padding: PaddingScheme,
        hash: Option<&H>,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::sign::<ThreadRng, _>(None, self, hash, digest),
            PaddingScheme::PSS => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }

    /// Sign the given digest.
    /// Use `rng` for blinding.
    pub fn sign_blinded<R: Rng, H: Hash>(
        &self,
        rng: &mut R,
        padding: PaddingScheme,
        hash: Option<&H>,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        match padding {
            PaddingScheme::PKCS1v15 => pkcs1v15::sign(Some(rng), self, hash, digest),
            PaddingScheme::PSS => unimplemented!("not yet implemented"),
            _ => Err(Error::InvalidPaddingScheme),
        }
    }
}

/// Check that the public key is well formed and has an exponent within acceptable bounds.
#[inline]
pub fn check_public(public_key: &impl PublicKey) -> Result<()> {
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
            n: BigUint::from_u64(100).unwrap(),
            e: BigUint::from_u64(200).unwrap(),
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
        use rand::SeedableRng;
        use rand_xorshift::XorShiftRng;
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

    #[test]
    fn invalid_coeff_private_key_regression() {
        let n = base64::decode("wC8GyQvTCZOK+iiBR5fGQCmzRCTWX9TQ3aRG5gGFk0wB6EFoLMAyEEqeG3gS8xhAm2rSWYx9kKufvNat3iWlbSRVqkcbpVAYlj2vTrpqDpJl+6u+zxFYoUEBevlJJkAhl8EuCccOA30fVpcfRvXPTtvRd3yFT9E9EwZljtgSI02w7gZwg7VIxaGeajh5Euz6ZVQZ+qNRKgXrRC7gPRqVyI6Dt0Jc+Su5KBGNn0QcPDzOahWha1ieaeMkFisZ9mdpsJoZ4tw5eicLaUomKzALHXQVt+/rcZSrCd6/7uUo11B/CYBM4UfSpwXaL88J9AE6A5++no9hmJzaF2LLp+Qwx4yY3j9TDutxSAjsraxxJOGZ3XyA9nG++Ybt3cxZ5fP7ROjxCfROBmVv5dYn0O9OBIqYeCH6QraNpZMadlLNIhyMv8Y+P3r5l/PaK4VJaEi5pPosnEPawp0W0yZDzmjk2z1LthaRx0aZVrAjlH0Rb/6goLUQ9qu1xsDtQVVpN4A89ZUmtTWORnnJr0+595eHHxssd2gpzqf4bPjNITdAEuOCCtpvyi4ls23zwuzryUYjcUOEnsXNQ+DrZpLKxdtsD/qNV/j1hfeyBoPllC3cV+6bcGOFcVGbjYqb+Kw1b0+jL69RSKQqgmS+qYqr8c48nDRxyq3QXhR8qtzUwBFSLVk=").unwrap();
        let e = base64::decode("AQAB").unwrap();
        let d = base64::decode("qQazSQ+FRN7nVK1bRsROMRB8AmsDwLVEHivlz1V3Td2Dr+oW3YUMgxedhztML1IdQJPq/ad6qErJ6yRFNySVIjDaxzBTOEoB1eHa1btOnBJWb8rVvvjaorixvJ6Tn3i4EuhsvVy9DoR1k4rGj3qSIiFjUVvLRDAbLyhpGgEfsr0Z577yJmTC5E8JLRMOKX8Tmxsk3jPVpsgd65Hu1s8S/ZmabwuHCf9SkdMeY/1bd/9i7BqqJeeDLE4B5x1xcC3z3scqDUTzqGO+vZPhjgprPDRlBamVwgenhr7KwCn8iaLamFinRVwOAag8BeBqOJj7lURiOsKQa9FIX1kdFUS1QMQxgtPycLjkbvCJjriqT7zWKsmJ7l8YLs6Wmm9/+QJRwNCEVdMTXKfCP1cJjudaiskEQThfUldtgu8gUDNYbQ/Filb2eKfiX4h1TiMxZqUZHVZyb9nShbQoXJ3vj/MGVF0QM8TxhXM8r2Lv9gDYU5t9nQlUMLhs0jVjai48jHABbFNyH3sEcOmJOIwJrCXw1dzG7AotwyaEVUHOmL04TffmwCFfnyrLjbFgnyOeoyIIBYjcY7QFRm/9nupXMTH5hZ2qrHfCJIp0KK4tNBdQqmnHapFl5l6Le1s4qBS5bEIzjitobLvAFm9abPlDGfxmY6mlrMK4+nytwF9Ct7wc1AE=").unwrap();
        let primes = vec![
            base64::decode("9kQWEAzsbzOcdPa+s5wFfw4XDd7bB1q9foZ31b1+TNjGNxbSBCFlDF1q98vwpV6nM8bWDh/wtbNoETSQDgpEnYOQ26LWEw6YY1+q1Q2GGEFceYUf+Myk8/vTc8TN6Zw0bKZBWy10Qo8h7xk4JpzuI7NcxvjJYTkS9aErFxi3vVH0aiZC0tmfaCqr8a2rJxyVwqreRpOjwAWrotMsf2wGsF4ofx5ScoFy5GB5fJkkdOrW1LyTvZAUCX3cstPr19+TNC5zZOk7WzZatnCkN5H5WzalWtZuu0oVL205KPOa3R8V2yv5e6fm0v5fTmqSuvjmaMJLXCN4QJkmIzojO99ckQ==").unwrap(),
            base64::decode("x8exdMjVA2CiI+Thx7loHtVcevoeE2sZ7btRVAvmBqo+lkHwxb7FHRnWvuj6eJSlD2f0T50EewIhhiW3R9BmktCk7hXjbSCnC1u9Oxc1IAUm/7azRqyfCMx43XhLxpD+xkBCpWkKDLxGczsRwTuaP3lKS3bSdBrNlGmdblubvVBIq4YZ2vXVlnYtza0cS+dgCK7BGTqUsrCUd/ZbIvwcwZkZtpkhj1KQfto9X/0OMurBzAqbkeq1cyRHXHkOfN/qbUIIRqr9Ii7Eswf9Vk8xp2O1Nt8nzcYS9PFD12M5eyaeFEkEYfpNMNGuTzp/31oqVjbpoCxS6vuWAZyADxhISQ==").unwrap(),
            base64::decode("is7d0LY4HoXszlC2NO7gejkq7XqL4p1W6hZJPYTNx+r37t1CC2n3Vvzg6kNdpRixDhIpXVTLjN9O7UO/XuqSumYKJIKoP52eb4Tg+a3hw5Iz2Zsb5lUTNSLgkQSBPAf71LHxbL82JL4g1nBUog8ae60BwnVArThKY4EwlJguGNw09BAU4lwf6csDl/nX2vfVwiAloYpeZkHL+L8m+bueGZM5KE2jEz+7ztZCI+T+E5i69rZEYDjx0lfLKlEhQlCW3HbCPELqXgNJJkRfi6MP9kXa9lSfnZmoT081RMvqonB/FUa4HOcKyCrw9XZEtnbNCIdbitfDVEX+pSSD7596wQ==").unwrap(),
            base64::decode("GPs0injugfycacaeIP5jMa/WX55VEnKLDHom4k6WlfDF4L4gIGoJdekcPEUfxOI5faKvHyFwRP1wObkPoRBDM0qZxRfBl4zEtpvjHrd5MibSyJkM8+J0BIKk/nSjbRIGeb3hV5O56PvGB3S0dKhCUnuVObiC+ne7izplsD4OTG70l1Yud33UFntyoMxrxGYLUSqhBMmZfHquJg4NOWOzKNY/K+EcHDLj1Kjvkcgv9Vf7ocsVxvpFdD9uGPceQ6kwRDdEl6mb+6FDgWuXVyqR9+904oanEIkbJ7vfkthagLbEf57dyG6nJlqh5FBZWxGIR72YGypPuAh7qnnqXXjY2Q==").unwrap(),
            base64::decode("CUWC+hRWOT421kwRllgVjy6FYv6jQUcgDNHeAiYZnf5HjS9iK2ki7v8G5dL/0f+Yf+NhE/4q8w4m8go51hACrVpP1p8GJDjiT09+RsOzITsHwl+ceEKoe56ZW6iDHBLlrNw5/MtcYhKpjNU9KJ2udm5J/c9iislcjgckrZG2IB8ADgXHMEByZ5DgaMl4AKZ1Gx8/q6KftTvmOT5rNTMLi76VN5KWQcDWK/DqXiOiZHM7Nr4dX4me3XeRgABJyNR8Fqxj3N1+HrYLe/zs7LOaK0++F9Ul3tLelhrhsvLxei3oCZkF9A/foD3on3luYA+1cRcxWpSY3h2J4/22+yo4+Q==").unwrap(),
        ];

        RSAPrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            BigUint::from_bytes_be(&e),
            BigUint::from_bytes_be(&d),
            primes
                .iter()
                .map(|p| BigUint::from_bytes_be(p))
                .collect(),
        );
    }
}
