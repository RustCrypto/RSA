#![cfg_attr(feature = "cargo-clippy", allow(clippy::many_single_char_names))]
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
/// Implemenation is based on the naive version from wikipedia.
#[inline]
fn mod_inverse(g: Cow<BigInt>, n: &BigInt) -> Option<BigInt> {
    assert!(g.as_ref() != n, "g must not be equal to n");
    assert!(!n.is_negative(), "negative modulus not supported");

    let n = n.abs();
    let g = if g.is_negative() {
        g.mod_floor(&n).to_biguint().unwrap()
    } else {
        g.to_biguint().unwrap()
    };

    let (d, x, _) = extended_gcd(&g, &n.to_biguint().unwrap());

    if !d.is_one() {
        return None;
    }

    if x.is_negative() {
        Some(x + n)
    } else {
        Some(x)
    }
}

/// Calculates the extended eucledian algorithm.
/// See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm for details.
/// The returned values are
/// - greatest common divisor (1)
/// - Bezout coefficients (2)
// TODO: implement optimized variants
pub fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigInt, BigInt, BigInt) {
    let mut a = BigInt::from_biguint(Plus, a.clone());
    let mut b = BigInt::from_biguint(Plus, b.clone());

    let mut ua = BigInt::one();
    let mut va = BigInt::zero();

    let mut ub = BigInt::zero();
    let mut vb = BigInt::one();

    let mut q;
    let mut tmp;
    let mut r;

    while !b.is_zero() {
        q = &a / &b;
        r = &a % &b;

        a = b;
        b = r;

        tmp = ua;
        ua = ub.clone();
        ub = tmp - &q * &ub;

        tmp = va;
        va = vb.clone();
        vb = tmp - &q * &vb;
    }

    (a, ua, va)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;
    use num_traits::FromPrimitive;
    use rand::thread_rng;

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
	    ["-10", "13"],
            ["-6193420858199668535", "2881"],
        ];

        for test in &tests {
            let element = BigInt::parse_bytes(test[0].as_bytes(), 10).unwrap();
            let modulus = BigInt::parse_bytes(test[1].as_bytes(), 10).unwrap();

            println!("{} modinv {}", element, modulus);
            let inverse = element.clone().mod_inverse(&modulus).unwrap();
            println!("inverse: {}", &inverse);
            let cmp = (inverse * &element).mod_floor(&modulus);

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
                for sign in vec![1i64, -1i64] {
                    let element = BigInt::from_i64(sign * x as i64).unwrap();
                    let gcd = element.gcd(&modulus);

                    if !gcd.is_one() {
                        continue;
                    }

                    let inverse = element.clone().mod_inverse(&modulus).unwrap();
                    let cmp = (&inverse * &element).mod_floor(&modulus);
                    println!("inverse: {}", &inverse);
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
            }
        }
    }

    #[test]
    fn test_extended_gcd_example() {
        // simple example for wikipedia
        let a = BigUint::from_u32(240).unwrap();
        let b = BigUint::from_u32(46).unwrap();
        let (q, s_k, t_k) = extended_gcd(&a, &b);

        assert_eq!(q, BigInt::from_i32(2).unwrap());
        assert_eq!(s_k, BigInt::from_i32(-9).unwrap());
        assert_eq!(t_k, BigInt::from_i32(47).unwrap());
    }

    #[test]
    fn test_extended_gcd_assumptions() {
        let mut rng = thread_rng();

        for i in 1..100 {
            let a = rng.gen_biguint(i * 128);
            let b = rng.gen_biguint(i * 128);
            let (q, s_k, t_k) = extended_gcd(&a, &b);

            let lhs = BigInt::from_biguint(Plus, a) * &s_k;
            let rhs = BigInt::from_biguint(Plus, b) * &t_k;
            assert_eq!(q, lhs + &rhs);
        }
    }

}
