//! Generation of random primes.

use num_bigint::BigUint;
use num_iter::range_step;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::Rng;

use prime::probably_prime;

/// A generic trait for generating random primes.
///
/// *Warning*: This is highly dependend on the provided random number generator,
/// to provide actually random primes.
///
/// # Example
/// ```
/// extern crate rand;
/// extern crate rsa;
///
/// use rand::thread_rng;
/// use rsa::RandPrime;
///
/// let mut rng = thread_rng();
/// let p = rng.gen_prime(1024);
/// assert_eq!(p.bits(), 1024);
/// ```
///
pub trait RandPrime {
    /// Generate a random prime number with as many bits as given.
    fn gen_prime(&mut self, usize) -> BigUint;
}

/// A list of small, prime numbers that allows us to rapidly
/// exclude some fraction of composite candidates when searching for a random
/// prime. This list is truncated at the point where smallPrimesProduct exceeds
/// a u64. It does not include two because we ensure that the candidates are
/// odd by construction.
const SMALL_PRIMES: [u8; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

lazy_static! {
    /// The product of the values in SMALL_PRIMES and allows us
    /// to reduce a candidate prime by this number and then determine whether it's
    /// coprime to all the elements of SMALL_PRIMES without further BigUint
    /// operations.
    static ref SMALL_PRIMES_PRODUCT: BigUint = BigUint::from_u64(16_294_579_238_595_022_365).unwrap();
}

impl<R: Rng + ?Sized> RandPrime for R {
    fn gen_prime(&mut self, bit_size: usize) -> BigUint {
        if bit_size < 2 {
            panic!("prime size must be at least 2-bit");
        }

        let mut b = bit_size % 8;
        if b == 0 {
            b = 8;
        }

        let bytes_len = (bit_size + 7) / 8;
        let mut bytes = vec![0u8; bytes_len];

        loop {
            self.fill_bytes(&mut bytes);
            // Clear bits in the first byte to make sure the candidate has a size <= bits.
            bytes[0] &= ((1u32 << (b as u32)) - 1) as u8;

            // Don't let the value be too small, i.e, set the most significant two bits.
            // Setting the top two bits, rather than just the top bit,
            // means that when two of these values are multiplied together,
            // the result isn't ever one bit short.
            if b >= 2 {
                bytes[0] |= 3u8.wrapping_shl(b as u32 - 2);
            } else {
                // Here b==1, because b cannot be zero.
                bytes[0] |= 1;
                if bytes_len > 1 {
                    bytes[1] |= 0x80;
                }
            }

            // Make the value odd since an even number this large certainly isn't prime.
            bytes[bytes_len - 1] |= 1u8;

            let mut p = BigUint::from_bytes_be(&bytes);
            // must always be a u64, as the SMALL_PRIMES_PRODUCT is a u64
            let rem = (&p % &*SMALL_PRIMES_PRODUCT).to_u64().unwrap();

            'next: for delta in range_step(0, 1 << 20, 2) {
                let m = rem + delta;

                for prime in &SMALL_PRIMES {
                    if m % u64::from(*prime) == 0 && (bit_size > 6 || m != u64::from(*prime)) {
                        continue 'next;
                    }
                }

                if delta > 0 {
                    p += BigUint::from_u64(delta).unwrap();
                }

                break;
            }

            // There is a tiny possibility that, by adding delta, we caused
            // the number to be one bit too long. Thus we check bit length here.
            if p.bits() == bit_size && probably_prime(&p, 20) {
                return p;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    #[test]
    fn test_prime_small() {
        let mut rng = StdRng::from_seed([0u8; 32]);
        for n in 2..10 {
            let p = rng.gen_prime(n);

            assert_eq!(p.bits(), n);
            assert!(probably_prime(&p, 32));
        }
    }

    #[test]
    fn test_gen_prime_1024() {
        let mut rng = StdRng::from_seed([0u8; 32]);
        let p = rng.gen_prime(1024);
        assert_eq!(p.bits(), 1024);
    }
}
