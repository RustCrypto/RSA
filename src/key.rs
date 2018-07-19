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

impl RSAPrivateKey {
    /// Generate a new RSA key pair of the given bit size using the passed in `rng`.
    pub fn new<R: Rng>(rng: &mut R, bit_size: usize) -> Result<RSAPrivateKey> {
        generate_multi_prime_key(rng, 2, bit_size)
    }

    /// Constructs an RSA key pair from the individual components.
    pub fn from_components(n: BigUint, e: u32, d: BigUint, primes: Vec<BigUint>) -> RSAPrivateKey {
        RSAPrivateKey { n, e, d, primes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::{FromPrimitive, ToPrimitive};

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
}
