#![cfg_attr(feature = "cargo-clippy", allow(many_single_char_names))]
use std::borrow::Cow;

use num_bigint::Sign::Plus;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};

/// Jacobi returns the Jacobi symbol (x/y), either +1, -1, or 0.
/// The y argument must be an odd integer.
pub fn jacobi(x: &BigInt, y: &BigInt) -> isize {
    if !y.is_odd() {
        panic!(
            "invalid arguments, y must be an odd integer,but got {:?}",
            y
        );
    }

    let mut a = x.clone();
    let mut b = y.clone();
    let mut j = 1;

    if b.is_negative() {
        if a.is_negative() {
            j = -1;
        }
        b = -b;
    }

    loop {
        if b.is_one() {
            return j;
        }
        if a.is_zero() {
            return 0;
        }

        a = a.mod_floor(&b);
        if a.is_zero() {
            return 0;
        }

        // a > 0

        // handle factors of 2 in a
        let s = a.trailing_zeros().unwrap();
        if s & 1 != 0 {
            let bmod8 = b.get_limb(0) & 7;
            if bmod8 == 3 || bmod8 == 5 {
                j = -j;
            }
        }

        let c = &a >> s; // a = 2^s*c

        // swap numerator and denominator
        if b.get_limb(0) & 3 == 3 && c.get_limb(0) & 3 == 3 {
            j = -j
        }

        a = b;
        b = c.clone();
    }
}

/// Generic trait to implement modular inverse
pub trait ModInverse<R: Sized>: Sized {
    /// Function to calculate the [modular multiplicative
    /// inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of an integer *a* modulo *m*.
    ///
    /// TODO: references
    /// Returns the modular inverse of `self`.
    /// If none exists it returns `None`.
    fn mod_inverse(self, m: R) -> Option<Self>;
}

impl<'a> ModInverse<&'a BigUint> for BigUint {
    fn mod_inverse(self, m: &'a BigUint) -> Option<BigUint> {
        match mod_inverse(
            Cow::Owned(BigInt::from_biguint(Plus, self)),
            &BigInt::from_biguint(Plus, m.clone()),
        ) {
            Some(res) => res.to_biguint(),
            None => None,
        }
    }
}

impl ModInverse<BigUint> for BigUint {
    fn mod_inverse(self, m: BigUint) -> Option<BigUint> {
        match mod_inverse(
            Cow::Owned(BigInt::from_biguint(Plus, self)),
            &BigInt::from_biguint(Plus, m),
        ) {
            Some(res) => res.to_biguint(),
            None => None,
        }
    }
}

impl<'a> ModInverse<&'a BigInt> for BigInt {
    fn mod_inverse(self, m: &'a BigInt) -> Option<BigInt> {
        mod_inverse(Cow::Owned(self), m)
    }
}

impl ModInverse<BigInt> for BigInt {
    fn mod_inverse(self, m: BigInt) -> Option<BigInt> {
        mod_inverse(Cow::Owned(self), &m)
    }
}

/// Calculate the modular inverse of `a`.
/// Implemenation is based on Algorithm 4 Shifting Euclidean algorithm in [1]
///
/// [1] Modular Inverse Algorithms Without Multiplications for Cryptographic Applications - Laszlo Hars
#[inline]
fn mod_inverse(a: Cow<BigInt>, m: &BigInt) -> Option<BigInt> {
    assert!(a.as_ref() != m, "a must not be equal to m");
    assert!(a.is_positive(), "does not yet work for negative numbers");

    let mut u: BigInt;
    let mut v: BigInt;
    let mut r: BigInt;
    let mut s: BigInt;

    if a.as_ref() < m {
        u = m.clone();
        v = a.into_owned();
        r = BigInt::zero();
        s = BigInt::one();
    } else {
        u = a.into_owned();
        v = m.clone();
        r = BigInt::one();
        s = BigInt::zero();
    }

    while v.bits() > 1 {
        let f = u.bits() - v.bits();
        if u.sign() == v.sign() {
            u -= &v << f;
            r -= &s << f;
        } else {
            u += &v << f;
            r += &s << f;
        }
        if u.bits() < v.bits() {
            ::std::mem::swap(&mut u, &mut v);
            ::std::mem::swap(&mut r, &mut s);
        }
    }

    if v.is_zero() {
        return None;
    }

    if v.is_negative() {
        s = -s;
    }

    if &s > m {
        return Some(s - m);
    }
    if s.is_negative() {
        return Some(s + m);
    }

    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::FromPrimitive;

    #[test]
    fn test_jacobi() {
        let cases = [
            [0, 1, 1],
            [0, -1, 1],
            [1, 1, 1],
            [1, -1, 1],
            [0, 5, 0],
            [1, 5, 1],
            [2, 5, -1],
            [-2, 5, -1],
            [2, -5, -1],
            [-2, -5, 1],
            [3, 5, -1],
            [5, 5, 0],
            [-5, 5, 0],
            [6, 5, 1],
            [6, -5, 1],
            [-6, 5, 1],
            [-6, -5, -1],
        ];

        for case in cases.iter() {
            let x = BigInt::from_i64(case[0]).unwrap();
            let y = BigInt::from_i64(case[1]).unwrap();

            assert_eq!(case[2] as isize, jacobi(&x, &y), "jacobi({}, {})", x, y);
        }
    }

    #[test]
    fn test_mod_inverse() {
        let tests = [
            ["1234567", "458948883992"],
	    ["239487239847", "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"],
            // TODO: enable, once algorithm works for negative numbers
	    // ["-10", "13"],
        ];

        for test in &tests {
            let element = BigInt::parse_bytes(test[0].as_bytes(), 10).unwrap();
            let modulus = BigInt::parse_bytes(test[1].as_bytes(), 10).unwrap();

            let inverse = element.clone().mod_inverse(&modulus).unwrap();
            let cmp = (inverse * &element) % &modulus;
            assert_eq!(
                cmp,
                BigInt::one(),
                "mod_inverse({}, {}) * {} % {} = {}, not 1",
                &element,
                &modulus,
                &element,
                &modulus,
                &cmp
            );
        }

        // exhaustive tests for small numbers
        for n in 2..100 {
            let modulus = BigInt::from_u64(n).unwrap();
            for x in 1..n {
                let element = BigInt::from_u64(x).unwrap();
                let gcd = element.gcd(&modulus);

                if !gcd.is_one() {
                    continue;
                }

                let inverse = element.clone().mod_inverse(&modulus).unwrap();
                let cmp = (&inverse * &element) % &modulus;
                assert_eq!(
                    cmp,
                    BigInt::one(),
                    "mod_inverse({}, {})*{}%{}={}, not 1",
                    &element,
                    &modulus,
                    &element,
                    &modulus,
                    &cmp
                );
            }
        }
    }
}
