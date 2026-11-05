//! Shared integer arithmetic for RSAEP/RSAVP1 and RSADP/RSASP1 (RFC8017 §5).
//!
//! These functions do not implement octet-string conversion or scheme encoding. In particular,
//! `rsa_encrypt` performs modular exponentiation without checking the representative's range;
//! callers implementing RSAEP or RSAVP1 must establish that the input is less than `n`.

pub(crate) use super::reduction::to_monty;

use super::blinding::{blind_exponent, pow_mod_blinded, totient};
use crypto_bigint::{
    BoxedUint, ConcatenatingMul, ConcatenatingSquare, Gcd, NonZero, Odd, RandomMod, Resize,
    modular::BoxedMontyParams,
};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};
use crate::traits::keys::{PrivateKeyParts, PublicKeyParts};

/// ⚠️ Raw RSA public-key operation on the integer representative `m`, without padding.
///
/// Computes the exponentiation shared by RSAEP (RFC8017 §5.1.1) and RSAVP1 (§5.2.2).
/// The caller must check that the representative is less than `n` to implement either primitive;
/// this function reduces out-of-range inputs modulo `n`.
///
/// <div class="warning">
/// <b> ☢️️ WARNING: HAZARDOUS API ☢️</b>
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
/// </div>
#[inline]
#[allow(clippy::missing_errors_doc, reason = "TODO")]
pub fn rsa_encrypt<K: PublicKeyParts>(key: &K, m: &BoxedUint) -> Result<BoxedUint> {
    let e = key.e();
    let res = pow_mod_params_vartime_exp_bits(m, e, e.bits(), key.n_params());
    Ok(res)
}

/// ⚠️ Performs the raw RSA private-key operation without padding or a CRT fault check.
///
/// Implements the integer arithmetic shared by RSADP (RFC8017 §5.1.2) and RSASP1 (§5.2.1).
/// Checks that `c < n` and that `c` has the modulus's storage precision.
///
/// Returns a plaintext `BoxedUint`. Performs base, exponent, and CRT modulus blinding if an `Rng`
/// is passed, using fresh factors for each private operation.
/// Blinded non-CRT operations require the prime factors in [`PrivateKeyParts::primes`].
///
/// <div class="warning">
/// <b> ☢️️ WARNING: HAZARDOUS API ☢️</b>
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
/// </div>
#[inline]
#[allow(clippy::missing_errors_doc, reason = "TODO")]
pub fn rsa_decrypt<R: TryCryptoRng + ?Sized>(
    mut rng: Option<&mut R>,
    priv_key: &impl PrivateKeyParts,
    c: &BoxedUint,
) -> Result<BoxedUint> {
    let n = priv_key.n();
    let d = priv_key.d();

    if c.bits_precision() != n.as_ref().bits_precision() {
        return Err(Error::Decryption);
    }

    if c >= n.as_ref() {
        return Err(Error::Decryption);
    }

    let mut ir = None;

    let n_params = priv_key.n_params();
    let c = if let Some(rng) = rng.as_deref_mut() {
        let (blinded, unblinder) = blind(rng, priv_key, c, n_params)?;
        ir = Some(unblinder);
        blinded
    } else {
        c.clone()
    };

    let is_multiprime = priv_key.primes().len() > 2;

    let m = match (
        priv_key.dp(),
        priv_key.dq(),
        priv_key.qinv(),
        priv_key.p(),
        priv_key.q(),
    ) {
        (Some(dp), Some(dq), Some(qinv), Some(p), Some(q)) if !is_multiprime => {
            // We have the precalculated values needed for the CRT.
            // precomputed: dP = (1/e) mod (p-1) = d mod (p-1)
            // precomputed: dQ = (1/e) mod (q-1) = d mod (q-1)

            // TODO(tarcieri): zeroize intermediates
            let p_params = BoxedMontyParams::from(p.clone());
            let q_params = BoxedMontyParams::from(q.clone());

            let blinded_exponents = if let Some(rng) = rng.as_deref_mut() {
                let pm1 = Zeroizing::new(p.modulus().wrapping_sub(BoxedUint::one()));
                let qm1 = Zeroizing::new(q.modulus().wrapping_sub(BoxedUint::one()));
                Some((
                    blind_exponent(rng, dp, &pm1)?,
                    blind_exponent(rng, dq, &qm1)?,
                ))
            } else {
                None
            };

            let (dp, dq) = blinded_exponents
                .as_ref()
                .map_or((dp, dq), |(dp, dq)| (&**dp, &**dq));

            // Exponentiate modulo independently blinded primes, then reduce both residues back
            // to the original primes before using the precomputed qInv for CRT recombination.
            let (mut m1, m2) = if let Some(rng) = rng {
                (
                    pow_mod_blinded(rng, &c, dp, &p_params)?,
                    pow_mod_blinded(rng, &c, dq, &q_params)?.retrieve(),
                )
            } else {
                (
                    to_monty(&c, &p_params).pow(dp),
                    to_monty(&c, &q_params).pow(dq).retrieve(),
                )
            };

            // (m1 - m2) mod p, also supporting custom keys with unequal public widths.
            let m2r = to_monty(&m2, &p_params);
            m1 -= &m2r;

            // precomputed: qInv = (1/q) mod p

            // h = qInv.(m1 - m2) mod p
            let h = (qinv * m1).retrieve();

            // m = m2 + h.q
            // With m2 < q and h < p, m < n even when the exponentiations used blinded moduli.
            let m2 = m2.try_resize(n.bits_precision()).ok_or(Error::Internal)?;
            let hq = h
                .concatenating_mul(priv_key.primes()[1].as_ref())
                .try_resize(n.bits_precision())
                .ok_or(Error::Internal)?;
            m2.wrapping_add(&hq)
        }
        _ => {
            // c^d (mod n)
            let blinded_d = if let Some(rng) = rng {
                let phi = totient(priv_key.primes(), n.bits_precision())?;
                Some(blind_exponent(rng, d, &phi)?)
            } else {
                None
            };

            pow_mod_params(&c, blinded_d.as_deref().unwrap_or(d), n_params)
        }
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
/// Returns a plaintext `BoxedUint`. Performs base, exponent, and CRT modulus blinding if an `Rng`
/// is passed, using fresh factors for each private operation.
/// Blinded non-CRT operations require the prime factors in [`PrivateKeyParts::primes`].
///
/// `c` must have the same `bits_precision` as the RSA key modulus.
///
/// <div class="warning">
/// <b> ☢️️ WARNING: HAZARDOUS API ☢️</b>
///
/// Use this function with great care! Raw RSA should never be used without an appropriate padding
/// or signature scheme. See the [module-level documentation][crate::hazmat] for more information.
/// </div>
#[inline]
#[allow(clippy::missing_errors_doc, reason = "TODO")]
pub fn rsa_decrypt_and_check<R: TryCryptoRng + ?Sized>(
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
fn blind<R: TryCryptoRng + ?Sized, K: PublicKeyParts>(
    rng: &mut R,
    key: &K,
    c: &BoxedUint,
    n_params: &BoxedMontyParams,
) -> Result<(BoxedUint, BoxedUint)> {
    // Blinding involves multiplying c by r^e.
    // Then the decryption operation performs (m^e * r^e)^d mod n
    // which equals mr mod n. The factor of r can then be removed
    // by multiplying by the multiplicative inverse of r.
    debug_assert_eq!(&key.n().clone().get(), n_params.modulus());
    let bits = key.n_bits_precision();

    let mut r: BoxedUint = BoxedUint::zero_with_precision(bits);
    let mut ir: Option<BoxedUint> = None;
    while ir.is_none() {
        r = BoxedUint::try_random_mod_vartime(rng, key.n()).map_err(|_| Error::Rng)?;

        // r^-1 (mod n)
        ir = r.invert_mod(key.n()).into();
    }

    let blinded = {
        // r^e (mod n)
        let e = key.e();
        let mut rpowe = pow_mod_params_vartime_exp_bits(&r, e, e.bits(), n_params);
        // c * r^e (mod n)
        let c = c.mul_mod(&rpowe, n_params.modulus().as_nz_ref());
        rpowe.zeroize();

        c
    };

    let ir = ir.expect("loop exited");
    debug_assert_eq!(blinded.bits_precision(), bits);
    debug_assert_eq!(ir.bits_precision(), bits);

    Ok((blinded, ir))
}

/// Given an m and unblinding factor, unblind the m.
fn unblind(m: &BoxedUint, unblinder: &BoxedUint, n_params: &BoxedMontyParams) -> BoxedUint {
    // m * r^-1 (mod n)
    debug_assert_eq!(
        m.bits_precision(),
        unblinder.bits_precision(),
        "invalid unblinder"
    );

    debug_assert_eq!(
        m.bits_precision(),
        n_params.bits_precision(),
        "invalid n_params"
    );

    m.mul_mod(unblinder, n_params.modulus().as_nz_ref())
}

/// Computes `base.pow_mod(exp, n)` with precomputed `n_params`.
///
/// Constant-time with respect to `base` and `exp`
fn pow_mod_params(base: &BoxedUint, exp: &BoxedUint, n_params: &BoxedMontyParams) -> BoxedUint {
    to_monty(base, n_params).pow(exp).retrieve()
}

/// Computes `base.pow_mod(exp, n)` with a bounded exponent and precomputed `n_params`.
///
/// Constant-time with respect to `base`. The exponent bit length `exp_bits` may be leaked in the
/// time pattern
fn pow_mod_params_vartime_exp_bits(
    base: &BoxedUint,
    exp: &BoxedUint,
    exp_bits: u32,
    n_params: &BoxedMontyParams,
) -> BoxedUint {
    to_monty(base, n_params)
        .pow_bounded_exp(exp, exp_bits)
        .retrieve()
}

/// The following (deterministic) algorithm also recovers the prime factors `p` and `q` of a modulus `n`, given the
/// public exponent `e` and private exponent `d` using the method described in
/// [NIST 800-56B Appendix C.2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf).
pub fn recover_primes(
    n: &NonZero<BoxedUint>,
    e: &BoxedUint,
    d: &BoxedUint,
) -> Result<(BoxedUint, BoxedUint)> {
    // Check precondition

    // Note: because e is at most u64::MAX, it is already
    // known to be < 2**256
    if e <= &BoxedUint::from(2u64.pow(16)) {
        return Err(Error::InvalidArguments);
    }

    // 1. Let a = (de – 1) × GCD(n – 1, de – 1).
    let bits = d.bits_precision() * 2;
    let one = BoxedUint::one_with_precision(bits);
    let e = e.resize_unchecked(d.bits_precision());
    let d = d.resize_unchecked(d.bits_precision());
    let n = n.resize_unchecked(bits);

    let a1 = d.concatenating_mul(&e) - &one;
    let a2 = (n.as_ref() - &one).gcd(&a1);
    let a = a1.concatenating_mul(&a2);
    let n = n.resize_unchecked(a.bits_precision());

    // 2. Let m = floor(a /n) and r = a – m n, so that a = m n + r and 0 ≤ r < n.
    let m = &a / &n;
    let r = a - m.concatenating_mul(&*n);
    let n = n.get();

    // 3. Let b = ( (n – r)/(m + 1) ) + 1; if b is not an integer or b^2 ≤ 4n, then output an error indicator,
    //    and exit without further processing.
    let modulus_check = (&n - &r) % NonZero::new(&m + &one).expect("adding 1");
    if (!modulus_check.is_zero()).into() {
        return Err(Error::InvalidArguments);
    }
    let b = ((&n - &r) / NonZero::new(&m + &one).expect("adding one")) + one;

    let four = BoxedUint::from(4u32);
    let four_n = n.concatenating_mul(&four);
    let b_squared = b.concatenating_square();

    if b_squared <= four_n {
        return Err(Error::InvalidArguments);
    }
    let b_squared_minus_four_n = b_squared - four_n;

    // 4. Let ϒ be the positive square root of b^2 – 4n; if ϒ is not an integer,
    //    then output an error indicator, and exit without further processing.
    let y = b_squared_minus_four_n.floor_sqrt();

    let y_squared = y.concatenating_square();
    let sqrt_is_whole_number = y_squared == b_squared_minus_four_n;
    if !sqrt_is_whole_number {
        return Err(Error::InvalidArguments);
    }

    let bits = core::cmp::max(b.bits_precision(), y.bits_precision());
    let two = NonZero::new(BoxedUint::from(2u64))
        .expect("2 is non zero")
        .resize_unchecked(bits);
    let p = (&b + &y) / &two;
    let q = (b - y) / two;

    Ok((p, q))
}

/// Compute the modulus of a key from its primes.
pub(crate) fn compute_modulus(primes: &[BoxedUint]) -> Odd<BoxedUint> {
    let mut primes = primes.iter();
    let mut out = primes.next().expect("must at least be one prime").clone();
    for p in primes {
        out = out.concatenating_mul(&p);
    }
    Odd::new(out).expect("modulus must be odd")
}

/// Compute the private exponent from its primes (p and q) and public exponent
/// This uses Euler's totient function
#[inline]
pub(crate) fn compute_private_exponent_euler_totient(
    primes: &[BoxedUint],
    exp: &BoxedUint,
) -> Result<BoxedUint> {
    if primes.len() < 2 {
        return Err(Error::InvalidPrime);
    }
    let bits = primes[0].bits_precision();
    let mut totient = BoxedUint::one_with_precision(bits);

    for prime in primes {
        totient = totient.concatenating_mul(&(prime - &BoxedUint::one()));
    }
    let exp = exp.resize_unchecked(totient.bits_precision());

    // NOTE: `mod_inverse` checks if `exp` evenly divides `totient` and returns `None` if so.
    // This ensures that `exp` is not a factor of any `(prime - 1)`.
    let totient = NonZero::new(totient).expect("known");
    match exp.invert_mod(&totient).into_option() {
        Some(res) => Ok(res),
        None => Err(Error::InvalidPrime),
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
    exp: &BoxedUint,
) -> Result<BoxedUint> {
    let one = BoxedUint::one();
    let p1 = p - &one;
    let q1 = q - &one;

    // LCM inlined
    let gcd = p1.gcd(&q1);
    let lcm = (p1 / NonZero::new(gcd).expect("gcd is non zero")).concatenating_mul(&q1);
    let exp = exp.resize_unchecked(lcm.bits_precision());
    if let Some(d) = exp.invert_mod(&NonZero::new(lcm).expect("non zero")).into() {
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
        let bits = 2048;

        let n = BoxedUint::from_be_hex(
            concat!(
                "d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222",
                "b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e",
                "74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb",
                "28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7",
                "ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078c",
                "c780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2",
                "e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf67",
                "76fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b"
            ),
            bits,
        )
        .unwrap();
        let e = BoxedUint::from(65_537u64);
        let d = BoxedUint::from_be_hex(
            concat!(
                "c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d7395832",
                "0dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92f",
                "ae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552",
                "e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f",
                "54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057",
                "fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0",
                "c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd87",
                "7d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341"
            ),
            bits,
        )
        .unwrap();
        let p = BoxedUint::from_be_hex(
            concat!(
                "f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd",
                "624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07b",
                "d405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159",
                "067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61"
            ),
            bits / 2,
        )
        .unwrap();
        let q = BoxedUint::from_be_hex(
            concat!(
                "da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7",
                "f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b",
                "961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909",
                "ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b"
            ),
            bits / 2,
        )
        .unwrap();

        let (mut p1, mut q1) = recover_primes(&NonZero::new(n).unwrap(), &e, &d).unwrap();

        if p1 < q1 {
            std::mem::swap(&mut p1, &mut q1);
        }
        assert_eq!(p, p1);
        assert_eq!(q, q1);
    }

    #[test]
    fn to_monty_matches_reference_reduction() {
        use crypto_bigint::{Odd, Resize};

        let n = Odd::new(
            BoxedUint::from_be_hex(
                concat!(
                    "d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222",
                    "b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e",
                    "74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb",
                    "28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7",
                    "ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078c",
                    "c780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2",
                    "e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf67",
                    "76fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b"
                ),
                2048,
            )
            .unwrap(),
        )
        .unwrap();
        let params = BoxedMontyParams::new(n.clone());
        let nz = n.as_nz_ref();

        let candidates = [
            BoxedUint::zero_with_precision(2048),
            BoxedUint::one_with_precision(2048),
            n.as_ref() - &BoxedUint::one(),
            n.as_ref().clone(),
            n.as_ref().wrapping_add(BoxedUint::one()),
            BoxedUint::max(2048),
            BoxedUint::from(12345u64),
            BoxedUint::max(4096),
            BoxedUint::max(2048)
                .resize(4096)
                .wrapping_add(BoxedUint::one()),
        ];
        for x in candidates {
            let expected = x.rem_vartime(nz).resize_unchecked(2048);
            assert_eq!(to_monty(&x, &params).retrieve(), expected);
        }
    }
}
