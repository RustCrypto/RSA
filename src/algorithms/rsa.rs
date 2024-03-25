//! Generic RSA implementation

use alloc::borrow::Cow;
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Gcd, InvMod, NonZero, Odd, RandomMod, Wrapping};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::errors::{Error, Result};
use crate::key::reduce;
use crate::traits::keys::{PrivateKeyParts, PublicKeyParts};

/// ⚠️ Raw RSA encryption of m with the public key. No padding is performed.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
#[inline]
pub fn rsa_encrypt<K: PublicKeyParts>(key: &K, m: &BoxedUint) -> Result<BoxedUint> {
    let res = pow_mod_params(m, &BoxedUint::from(key.e()), key.n_params());
    Ok(res)
}

/// ⚠️ Performs raw RSA decryption with no padding or error checking.
///
/// Returns a plaintext `BoxedUint`. Performs RSA blinding if an `Rng` is passed.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
#[inline]
pub fn rsa_decrypt<R: CryptoRngCore + ?Sized>(
    mut rng: Option<&mut R>,
    priv_key: &impl PrivateKeyParts,
    c: &BoxedUint,
) -> Result<BoxedUint> {
    let n = priv_key.n();
    let d = priv_key.d();

    if c >= n.as_ref() {
        return Err(Error::Decryption);
    }

    let mut ir = None;

    let n_params = priv_key.n_params();

    let c = if let Some(ref mut rng) = rng {
        let (blinded, unblinder) = blind(rng, priv_key, &c, &n_params);
        ir = Some(unblinder);
        Cow::Owned(blinded)
    } else {
        Cow::Borrowed(c)
    };

    let has_precomputes = priv_key.dp().is_some();
    let is_multiprime = priv_key.primes().len() > 2;

    let m = if is_multiprime || !has_precomputes {
        // c^d (mod n)
        pow_mod_params(&c, &d, n_params.clone())
    } else {
        // We have the precalculated values needed for the CRT.

        let dp = priv_key.dp().unwrap();
        let dq = priv_key.dq().unwrap();
        let qinv = priv_key.qinv().unwrap();
        let p_params = priv_key.p_params().unwrap();
        let q_params = priv_key.q_params().unwrap();

        let _p = &priv_key.primes()[0];
        let q = &priv_key.primes()[1];

        // precomputed: dP = (1/e) mod (p-1) = d mod (p-1)
        // precomputed: dQ = (1/e) mod (q-1) = d mod (q-1)

        // m1 = c^dP mod p
        let cp = BoxedMontyForm::new(c.clone().into_owned(), p_params.clone());
        let mut m1 = cp.pow(&dp);
        // m2 = c^dQ mod q
        let cq = BoxedMontyForm::new(c.into_owned(), q_params.clone());
        let m2 = cq.pow(&dq).retrieve();

        // (m1 - m2) mod p = (m1 mod p) - (m2 mod p) mod p
        let m2r = BoxedMontyForm::new(m2.clone(), p_params.clone());
        m1 -= &m2r;

        // precomputed: qInv = (1/q) mod p

        // h = qInv.(m1 - m2) mod p
        let mut m: Wrapping<BoxedUint> = Wrapping(qinv.mul(&m1).retrieve());

        // m = m2 + h.q
        m *= Wrapping(q.clone());
        m += Wrapping(m2);
        m.0
    };

    match ir {
        Some(ref ir) => {
            // unblind
            let res = unblind(&m, ir, n_params);
            Ok(res)
        }
        None => Ok(m),
    }
}

/// ⚠️ Performs raw RSA decryption with no padding.
///
/// Returns a plaintext `BoxedUint`. Performs RSA blinding if an `Rng` is passed.  This will also
/// check for errors in the CRT computation.
///
/// # ☢️️ WARNING: HAZARDOUS API ☢️
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
#[inline]
pub fn rsa_decrypt_and_check<R: CryptoRngCore + ?Sized>(
    priv_key: &impl PrivateKeyParts,
    rng: Option<&mut R>,
    c: &BoxedUint,
) -> Result<BoxedUint> {
    let m = rsa_decrypt(rng, priv_key, c)?;

    // In order to defend against errors in the CRT computation, m^e is
    // calculated, which should match the original ciphertext.
    let check = rsa_encrypt(priv_key, &m)?;

    if c != &check {
        return Err(Error::Internal);
    }

    Ok(m)
}

/// Returns the blinded c, along with the unblinding factor.
fn blind<R: CryptoRngCore, K: PublicKeyParts>(
    rng: &mut R,
    key: &K,
    c: &BoxedUint,
    n_params: &BoxedMontyParams,
) -> (BoxedUint, BoxedUint) {
    // Blinding involves multiplying c by r^e.
    // Then the decryption operation performs (m^e * r^e)^d mod n
    // which equals mr mod n. The factor of r can then be removed
    // by multiplying by the multiplicative inverse of r.
    debug_assert_eq!(&key.n().clone().get(), n_params.modulus());

    let mut r: BoxedUint = BoxedUint::one();
    let mut ir: Option<BoxedUint> = None;
    while ir.is_none() {
        r = BoxedUint::random_mod(rng, key.n());
        if r.is_zero().into() {
            r = BoxedUint::one();
        }

        // r^-1 (mod n)
        ir = r.inv_mod(key.n()).into();
    }

    let blinded = {
        // r^e (mod n)
        let mut rpowe = pow_mod_params(&r, &BoxedUint::from(key.e()), n_params.clone());
        // c * r^e (mod n)
        let c = mul_mod_params(c, &rpowe, n_params.clone());
        rpowe.zeroize();

        c
    };

    (blinded, ir.unwrap())
}

/// Given an m and and unblinding factor, unblind the m.
fn unblind(m: &BoxedUint, unblinder: &BoxedUint, n_params: BoxedMontyParams) -> BoxedUint {
    // m * r^-1 (mod n)
    mul_mod_params(m, unblinder, n_params)
}

/// Computes `base.pow_mod(exp, n)` with precomputed `n_params`.
fn pow_mod_params(base: &BoxedUint, exp: &BoxedUint, n_params: BoxedMontyParams) -> BoxedUint {
    let base = reduce(&base, n_params);
    base.pow(exp).retrieve()
}

/// Computes `lhs.mul_mod(rhs, n)` with precomputed `n_params`.
fn mul_mod_params(lhs: &BoxedUint, rhs: &BoxedUint, n_params: BoxedMontyParams) -> BoxedUint {
    // TODO: nicer api in crypto-bigint?
    let lhs = BoxedMontyForm::new(lhs.clone(), n_params.clone());
    let rhs = BoxedMontyForm::new(rhs.clone(), n_params);
    (lhs * rhs).retrieve()
}

/// The following (deterministic) algorithm also recovers the prime factors `p` and `q` of a modulus `n`, given the
/// public exponent `e` and private exponent `d` using the method described in
/// [NIST 800-56B Appendix C.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf).
pub fn recover_primes(
    n: &NonZero<BoxedUint>,
    e: u64,
    d: &BoxedUint,
) -> Result<(BoxedUint, BoxedUint)> {
    // Check precondition
    if e <= 2u64.pow(16) || e >= 2u64.pow(256) {
        return Err(Error::InvalidArguments);
    }

    // 1. Let a = (de – 1) × GCD(n – 1, de – 1).
    let one = BoxedUint::one();
    let e = BoxedUint::from(e);

    let a1 = d * &e - &one;
    let a2 = (n.as_ref() - &one).gcd(&(d * e - &one)).unwrap();
    let a = a1 * a2;

    // 2. Let m = floor(a /n) and r = a – m n, so that a = m n + r and 0 ≤ r < n.
    let m = &a / n;
    let r = a - &m * n.as_ref();

    // 3. Let b = ( (n – r)/(m + 1) ) + 1; if b is not an integer or b^2 ≤ 4n, then output an error indicator,
    //    and exit without further processing.
    let modulus_check = (n.as_ref() - &r) % NonZero::new(&m + &one).unwrap();
    if (!modulus_check.is_zero()).into() {
        return Err(Error::InvalidArguments);
    }
    let b = (n.as_ref() - &r) / NonZero::new((&m + &one) + one).unwrap();

    let four = BoxedUint::from(4u32);
    let four_n = n.as_ref() * four;
    let b_squared = b.square();
    if b_squared <= four_n {
        return Err(Error::InvalidArguments);
    }
    let b_squared_minus_four_n = b_squared - four_n;

    // 4. Let ϒ be the positive square root of b^2 – 4n; if ϒ is not an integer,
    //    then output an error indicator, and exit without further processing.
    let y = b_squared_minus_four_n.sqrt();

    let y_squared = y.square();
    let sqrt_is_whole_number = y_squared == b_squared_minus_four_n;
    if !sqrt_is_whole_number {
        return Err(Error::InvalidArguments);
    }

    let two = NonZero::new(BoxedUint::from(2u64)).unwrap();
    let p = (&b + &y) / &two;
    let q = (b - y) / two;

    Ok((p, q))
}

/// Compute the modulus of a key from its primes.
pub(crate) fn compute_modulus(primes: &[BoxedUint]) -> Odd<BoxedUint> {
    let mut out = primes[0].clone();
    for p in &primes[1..] {
        out = out * p;
    }
    Odd::new(out).unwrap()
}

/// Compute the private exponent from its primes (p and q) and public exponent
/// This uses Euler's totient function
#[inline]
pub(crate) fn compute_private_exponent_euler_totient(
    primes: &[BoxedUint],
    exp: u64,
) -> Result<BoxedUint> {
    if primes.len() < 2 {
        return Err(Error::InvalidPrime);
    }

    let mut totient = BoxedUint::one();

    for prime in primes {
        totient = totient * (prime - &BoxedUint::one());
    }
    let totient = Odd::new(totient).unwrap();

    // NOTE: `mod_inverse` checks if `exp` evenly divides `totient` and returns `None` if so.
    // This ensures that `exp` is not a factor of any `(prime - 1)`.
    if let Some(d) = BoxedUint::from(exp).inv_odd_mod(&totient).into() {
        Ok(d)
    } else {
        // `exp` evenly divides `totient`
        Err(Error::InvalidPrime)
    }
}

/// Compute the private exponent from its primes (p and q) and public exponent
///
/// This is using the method defined by
/// [NIST 800-56B Section 6.2.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf#page=47).
/// (Carmichael function)
///
/// FIPS 186-4 **requires** the private exponent to be less than λ(n), which would
/// make Euler's totiem unreliable.
#[inline]
pub(crate) fn compute_private_exponent_carmicheal(
    p: &BoxedUint,
    q: &BoxedUint,
    exp: u64,
) -> Result<BoxedUint> {
    let p1 = p - &BoxedUint::one();
    let q1 = q - &BoxedUint::one();

    let lcm = p1; // TODO: p1.lcm(&q1);
    let lcm = Odd::new(lcm).unwrap();
    if let Some(d) = BoxedUint::from(exp).inv_odd_mod(&lcm).into() {
        Ok(d)
    } else {
        // `exp` evenly divides `lcm`
        Err(Error::InvalidPrime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_primes_works() {
        let bits = 512;

        let n = BoxedUint::from_be_hex("00d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b", bits).unwrap();
        let e = 65537;
        let d = BoxedUint::from_be_hex("00c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d73958320dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92fae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd877d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341", bits).unwrap();
        let p = BoxedUint::from_be_hex("00f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07bd405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61", bits).unwrap();
        let q = BoxedUint::from_be_hex("00da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b", bits).unwrap();

        let (mut p1, mut q1) = recover_primes(&NonZero::new(n).unwrap(), e, &d).unwrap();

        if p1 < q1 {
            std::mem::swap(&mut p1, &mut q1);
        }
        assert_eq!(p, p1);
        assert_eq!(q, q1);
    }
}
