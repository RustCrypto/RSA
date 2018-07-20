use num_bigint::BigUint;
use rand::Rng;

use algorithms::generate_multi_prime_key;
use errors::Result;

/// Represents the public part of an RSA key.
pub struct RSAPublicKey {
    n: BigUint,
    e: u32,
}

/// Represents a whole RSA key, public and private parts.
pub struct RSAPrivateKey {
    /// Modulus
    n: BigUint,
    /// Public exponent
    e: u32,
    /// Private exponent
    d: BigUint,
    /// Prime factors of N, contains >= 2 elements.
    primes: Vec<BigUint>,
}

impl From<RSAPrivateKey> for RSAPublicKey {
    fn from(private_key: RSAPrivateKey) -> Self {
        RSAPublicKey {
            n: private_key.n.clone(),
            e: private_key.e,
        }
    }
}

/// Generic trait for operations on a public key.
pub trait PublicKey {
    /// Returns the modulus of the key.
    fn n(&self) -> &BigUint;
    /// Returns the public exponent of the key.
    fn e(&self) -> u32;
}

impl PublicKey for RSAPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> u32 {
        self.e
    }
}

impl<'a> PublicKey for &'a RSAPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> u32 {
        self.e
    }
}

impl PublicKey for RSAPrivateKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> u32 {
        self.e
    }
}

impl<'a> PublicKey for &'a RSAPrivateKey {
    fn n(&self) -> &BigUint {
        &self.n
    }

    fn e(&self) -> u32 {
        self.e
    }
}

impl RSAPrivateKey {
    /// Generate a new RSA key pair of the given bit size using the passed in `rng`.
    pub fn new<R: Rng>(rng: &mut R, bit_size: usize) -> Result<RSAPrivateKey> {
        generate_multi_prime_key(rng, 2, bit_size)
    }

    /// Constructs an RSA key pair from the individual components.
    pub fn from_components(n: BigUint, e: u32, d: BigUint, primes: Vec<BigUint>) -> RSAPrivateKey {
        RSAPrivateKey { n, e, d, primes }
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

        Ok(())
    }
}

fn check_public(public_key: &impl PublicKey) -> Result<()> {
    if public_key.e() < 2 {
        return Err(format_err!("public exponent too small"));
    }

    if public_key.e() > 1 << (31 - 1) {
        return Err(format_err!("public exponent too large"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{FromPrimitive, ToPrimitive};
    use rand::thread_rng;

    #[test]
    fn test_from_into() {
        let private_key = RSAPrivateKey {
            n: BigUint::from_u64(100).unwrap(),
            e: 200,
            d: BigUint::from_u64(123).unwrap(),
            primes: vec![],
        };
        let public_key: RSAPublicKey = private_key.into();

        assert_eq!(public_key.n().to_u64(), Some(100));
        assert_eq!(public_key.e(), 200);
    }

    fn test_key_basics(private_key: RSAPrivateKey) {
        private_key.validate().expect("failed to validate");

        assert!(
            private_key.d() < private_key.n(),
            "private exponent too large"
        );

        // TODO: encrypt and decrypt, once implemented
    }

    macro_rules! key_generation {
        ($name:ident, $multi:expr, $size:expr) => {
            #[test]
            fn $name() {
                let mut rng = thread_rng();
                let private_key = if $multi == 2 {
                    RSAPrivateKey::new(&mut rng, $size).unwrap()
                } else {
                    generate_multi_prime_key(&mut rng, $multi, $size).unwrap()
                };
                assert_eq!(private_key.n().bits(), $size);

                test_key_basics(private_key);
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
}
