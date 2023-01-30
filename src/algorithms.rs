//! Useful algorithms related to RSA.

use digest::{Digest, DynDigest, FixedOutputReset};
use num_bigint::traits::ModInverse;
use num_bigint::{BigUint, RandBigInt, RandPrime};
#[allow(unused_imports)]
use num_traits::Float;
use num_traits::{FromPrimitive, One, Zero};
use rand_core::CryptoRngCore;

use crate::errors::{Error, Result};
use crate::key::RsaPrivateKey;

/// Default exponent for RSA keys.
const EXP: u64 = 65537;

/// Generates a multi-prime RSA keypair of the given bit size,
/// and the given random source, as suggested in [1]. Although the public
/// keys are compatible (actually, indistinguishable) from the 2-prime case,
/// the private keys are not. Thus it may not be possible to export multi-prime
/// private keys in certain formats or to subsequently import them into other
/// code.
///
/// Uses default public key exponent of `65537`. If you want to use a custom
/// public key exponent value, use `algorithms::generate_multi_prime_key_with_exp`
/// instead.
///
/// Table 1 in [2] suggests maximum numbers of primes for a given size.
///
/// [1]: https://patents.google.com/patent/US4405829A/en
/// [2]: https://cacr.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
pub fn generate_multi_prime_key<R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    nprimes: usize,
    bit_size: usize,
) -> Result<RsaPrivateKey> {
    let exp = BigUint::from_u64(EXP).expect("invalid static exponent");
    generate_multi_prime_key_with_exp(rng, nprimes, bit_size, &exp)
}

/// Generates a multi-prime RSA keypair of the given bit size, public exponent,
/// and the given random source, as suggested in [1]. Although the public
/// keys are compatible (actually, indistinguishable) from the 2-prime case,
/// the private keys are not. Thus it may not be possible to export multi-prime
/// private keys in certain formats or to subsequently import them into other
/// code.
///
/// Table 1 in [2] suggests maximum numbers of primes for a given size.
///
/// [1]: https://patents.google.com/patent/US4405829A/en
/// [2]: http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
pub fn generate_multi_prime_key_with_exp<R: CryptoRngCore + ?Sized>(
    rng: &mut R,
    nprimes: usize,
    bit_size: usize,
    exp: &BigUint,
) -> Result<RsaPrivateKey> {
    if nprimes < 2 {
        return Err(Error::NprimesTooSmall);
    }

    if bit_size < 64 {
        let prime_limit = (1u64 << (bit_size / nprimes) as u64) as f64;

        // pi aproximates the number of primes less than prime_limit
        let mut pi = prime_limit / (prime_limit.ln() - 1f64);
        // Generated primes start with 0b11, so we can only use a quarter of them.
        pi /= 4f64;
        // Use a factor of two to ensure that key generation terminates in a
        // reasonable amount of time.
        pi /= 2f64;

        if pi < nprimes as f64 {
            return Err(Error::TooFewPrimes);
        }
    }

    let mut primes = vec![BigUint::zero(); nprimes];
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

        if let Some(d) = exp.mod_inverse(totient) {
            n_final = n;
            d_final = d.to_biguint().unwrap();
            break;
        }
    }

    RsaPrivateKey::from_components(n_final, exp.clone(), d_final, primes)
}

/// Mask generation function.
///
/// Panics if out is larger than 2**32. This is in accordance with RFC 8017 - PKCS #1 B.2.1
pub fn mgf1_xor(out: &mut [u8], digest: &mut dyn DynDigest, seed: &[u8]) {
    let mut counter = [0u8; 4];
    let mut i = 0;

    const MAX_LEN: u64 = core::u32::MAX as u64 + 1;
    assert!(out.len() as u64 <= MAX_LEN);

    while i < out.len() {
        let mut digest_input = vec![0u8; seed.len() + 4];
        digest_input[0..seed.len()].copy_from_slice(seed);
        digest_input[seed.len()..].copy_from_slice(&counter);

        digest.update(digest_input.as_slice());
        let digest_output = &*digest.finalize_reset();
        let mut j = 0;
        loop {
            if j >= digest_output.len() || i >= out.len() {
                break;
            }

            out[i] ^= digest_output[j];
            j += 1;
            i += 1;
        }
        inc_counter(&mut counter);
    }
}

/// Mask generation function.
///
/// Panics if out is larger than 2**32. This is in accordance with RFC 8017 - PKCS #1 B.2.1
pub fn mgf1_xor_digest<D>(out: &mut [u8], digest: &mut D, seed: &[u8])
where
    D: Digest + FixedOutputReset,
{
    let mut counter = [0u8; 4];
    let mut i = 0;

    const MAX_LEN: u64 = core::u32::MAX as u64 + 1;
    assert!(out.len() as u64 <= MAX_LEN);

    while i < out.len() {
        Digest::update(digest, seed);
        Digest::update(digest, counter);

        let digest_output = digest.finalize_reset();
        let mut j = 0;
        loop {
            if j >= digest_output.len() || i >= out.len() {
                break;
            }

            out[i] ^= digest_output[j];
            j += 1;
            i += 1;
        }
        inc_counter(&mut counter);
    }
}
fn inc_counter(counter: &mut [u8; 4]) {
    for i in (0..4).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            // No overflow
            return;
        }
    }
}

/// TODO
/// Probabilistic algorithm that given `d` returns `p` and `q`
pub fn recover_primes(n: &BigUint, e: &BigUint, d: &BigUint) -> Result<(BigUint, BigUint)> {
    const ITER_LIMIT: usize = 100;
    use num_integer::Integer;
    use rand_core::OsRng;
    let one = BigUint::one();

    // decompose e·d - 1 in odd and even components: r·2^t
    let mut r = (e * d) - &one;
    if r.is_odd() {
        return Err(Error::InvalidArguments);
    }
    let mut t = BigUint::zero();
    while r.is_even() {
        t += 1_u8;
        r >>= 1;
    }

    let n_min1 = n - &one;
    let two = 2_u8.into();

    for _ in 0..ITER_LIMIT {
        let mut g = OsRng.gen_biguint_range(&two, &n);
        let q = n.gcd(&g);
        if !q.is_one() {
            // if we are so lucky, we already found a factor.
            return Ok((g, q));
        }

        g = g.modpow(&r, &n);
        if g.is_one() || g == n_min1 {
            continue;
        }

        let mut count = BigUint::one();
        while count < t {
            let g_next = g.modpow(&two, n);
            if g_next.is_one() {
                // x^2 - 1 = (x-1)(x+1) = 0 (mod n)  then   n | (x-1)(x+1)
                let g = (g - &one) % n;
                let p = n.gcd(&g);
                let q = n / &p;
                return Ok((p, q));
            } else if g_next == n_min1 {
                continue;
            }
            g = g_next;
            count += &one;
        }
    }

    Err(Error::InvalidArguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_primes_works() {
        let n = BigUint::parse_bytes(b"00d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b", 16).unwrap();
        let e = BigUint::from_u64(65537).unwrap();
        let d = BigUint::parse_bytes(b"00c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d73958320dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92fae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd877d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341", 16).unwrap();
        let p = BigUint::parse_bytes(b"00f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07bd405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61",16).unwrap();
        let q = BigUint::parse_bytes(b"00da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b", 16).unwrap();

        let (mut p1, mut q1) = recover_primes(&n, &e, &d).unwrap();

        if p1 < q1 {
            std::mem::swap(&mut p1, &mut q1);
        }
        assert_eq!(p, p1);
        assert_eq!(q, q1);
    }
}
