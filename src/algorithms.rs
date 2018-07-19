use rand::Rng;

use errors::Result;
use key::RSAPrivateKey;
use math::ModInverse;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};
use prime_rand::RandPrime;

const EXP: u32 = 65537;

// Generates a multi-prime RSA keypair of the given bit
// size and the given random source, as suggested in [1]. Although the public
// keys are compatible (actually, indistinguishable) from the 2-prime case,
// the private keys are not. Thus it may not be possible to export multi-prime
// private keys in certain formats or to subsequently import them into other
// code.
//
// Table 1 in [2] suggests maximum numbers of primes for a given size.
//
// [1] US patent 4405829 (1972, expired)
// [2] http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
pub fn generate_multi_prime_key<R: Rng>(
    rng: &mut R,
    nprimes: usize,
    bit_size: usize,
) -> Result<RSAPrivateKey> {
    assert!(nprimes >= 2, "nprimes must be >= 2");

    if bit_size < 64 {
        let prime_limit = 1u32.wrapping_shl((bit_size / nprimes) as u32) as f32;
        // pi aproximates the number of primes less than prime_limit
        let mut pi = prime_limit / (prime_limit.log2() - 1f32);
        // Generated primes start with 0b11, so we can only use a quarter of them.
        pi /= 4f32;
        // Use a factor of two to ensure taht key generation terminates in a
        // reasonable amount of time.
        pi /= 2f32;
        if pi < (nprimes as f32) {
            return Err(format_err!(
                "too few primes of given length to generate an RSA key"
            ));
        }
    }

    let mut primes = Vec::with_capacity(nprimes);
    let n_final: BigUint;
    let d_final: BigUint;

    'next: loop {
        let mut todo = bit_size;
        // `gen_prime` should set the top two bits in each prime.
        // Thus each prime has the form
        //   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
        // And the product is:
        //   P = 2^todo × α
        // where α is the product of nprimes numbers of the form 0.11...
        //
        // If α < 1/2 (which can happen for nprimes > 2), we need to
        // shift todo to compensate for lost bits: the mean value of 0.11...
        // is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
        // will give good results.
        if nprimes >= 7 {
            todo += (nprimes - 2) / 5;
        }

        for (i, prime) in primes.iter_mut().enumerate() {
            *prime = rng.gen_prime(todo / (nprimes - i));
            todo -= prime.bits();
        }

        // Makes sure that primes is pairwise unequal.
        for (i, prime1) in primes.iter().enumerate() {
            for prime2 in primes.iter().take(i) {
                if prime1 == prime2 {
                    continue 'next;
                }
            }
        }

        let mut n = BigUint::one();
        let mut totient = BigUint::one();

        for prime in &primes {
            n *= prime;
            totient *= prime - BigUint::one();
        }

        if n.bits() != bit_size {
            // This should never happen for nprimes == 2 because
            // gen_prime should set the top two bits in each prime.
            // For nprimes > 2 we hope it does not happen often.
            continue 'next;
        }

        let exp = BigUint::from_u64(EXP as u64).unwrap();
        if let Some(d) = exp.mod_inverse(totient) {
            n_final = n;
            d_final = d;
            break;
        }
    }

    Ok(RSAPrivateKey::from_components(
        n_final, EXP, d_final, primes,
    ))
}
